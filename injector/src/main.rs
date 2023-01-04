extern crate core;

#[cfg(target_os = "macos")]
mod mach_pt;
mod shell_code;
mod thread_state;

use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt::format;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::{env, fmt, ptr};
use std::arch::asm;
use std::borrow::Borrow;
use std::ptr::null;
use regex::Regex;
use libc::{c_int, cc_t, getpid, kill, mach_port_t, mach_task_self, mach_task_self_, mach_vm_address_t, mach_vm_map, mach_vm_size_t, pid_t, PT_ATTACH, PT_READ_D, PT_READ_U, PT_TRACE_ME, ptrace, RTLD_NOW, SIGSTOP, task_for_pid, uint64_t, vm_deallocate, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, WIFSTOPPED, WSTOPSIG};
use mach::thread_act::thread_get_state;
use mach::vm_types::vm_address_t;

macro_rules! add {
 // macth like arm for macro
    ($a:expr,$b:expr)=>{
 // macro expand to this code
        {
// $a and $b will be templated using the value/variable provided to macro
            $a+$b
        }
    }
}

macro_rules! str_to_cstr {
    ($s:expr) => {
        CStr::from_bytes_with_nul(concat!($s, "\0").as_bytes()).unwrap()
    };
}

macro_rules! str_idents_to_cstr {
    ($s:ident) => {
    CStr::from_bytes_with_nul(format!("{}\0",$s).as_bytes()).unwrap()
    };
}


// marco_rules! to_cstr {
//      ($func_name:ident) => (
//           let cstring= CString::new(s).expect("failed to CString.new()");
//     let cstr = CStr::from_bytes_with_nul_unchecked(cstring.to_bytes_with_nul());
//
//     )
//
//     // let mut m=s.to_string();
//     // let eos="\0".to_string();
//     // m+=&eos;
//     // let data=m.as_bytes();
//     //  CStr::from_bytes_with_nul_unchecked(data)
// }

#[cfg(target_os = "macos")]
fn get_libc_handle() -> *mut c_void {
    unsafe {
        let dylib_path = ("/usr/lib/system/libsystem_c.dylib");

        let handle = dlopen_rust((dylib_path), libc::RTLD_LAZY);
        return handle;
    }
}

#[cfg(target_os = "linux")]
fn get_libc_handle() -> *mut c_void {
    unsafe {
        let dylib_path = ("libc.so");

        let handle = dlopen_rust((dylib_path), libc::RTLD_LAZY);
        return handle;
    }
}

fn dlopen_rust(path: &str, flag: c_int) -> *mut c_void {
    let m = format!("{}\0", path);
    let name_bytes = m.as_bytes();
    unsafe {
        let name_cstr = CStr::from_bytes_with_nul(name_bytes).unwrap();
        let addr = libc::dlopen(name_cstr.as_ptr(), flag);
        return addr;
    }
}

fn dlsym_rust(handle: *mut c_void, symbol_name: &str) -> *mut c_void {
    unsafe {
        let m = format!("{}\0", symbol_name);
        let name_bytes = m.as_bytes();
        let name_cstr = CStr::from_bytes_with_nul(name_bytes).expect("failed to convert to CStr");
        let addr = libc::dlsym(handle, name_cstr.as_ptr());
        return addr;
    }
}

#[cfg(target_os = "macos")]
fn get_libc_loadbase(pid: pid_t) -> i64 {
    let output = Command::new("vmmap")
        .arg(format!("{}", pid))
        .output()
        .expect("Failed to execute command");
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let expr =
        Regex::new(r"__TEXT +(\d+)-\d+ +\[.+] r-x/r-x SM=COW .+/usr/lib/system/libsystem_c.dylib").unwrap();
    let mut base_addr = 0;
    for mat in expr.captures_iter(&*stdout_str.to_string()) {
        println!("{}", &mat[0]);
        let base_addr_str = format!("{}", &mat[1]);
        println!("possible libc addr:0x{}", base_addr_str);
        base_addr = i64::from_str_radix(&*base_addr_str, 16).unwrap();
        break;
    }
    return base_addr;
}

fn getpid_rust() -> pid_t {
    unsafe {
        let self_pid = libc::getpid();
        return self_pid;
    }
}

fn fork_rust() -> pid_t {
    unsafe {
        let child_pid = libc::fork();
        return child_pid;
    }
}

fn get_libc_loadbase_linux(pid: pid_t) {
    let output = Command::new("cat")
        .arg(format!("/proc/{}/maps", pid))
        .output()
        .expect("Failed to execute command");
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let expr =
        Regex::new(r"__TEXT +(\d+)-\d+ +\[.+] r-x/r-x SM=COW .+/usr/lib/system/libsystem_c.dylib").unwrap();
    for mat in expr.find_iter(&*stdout_str.to_string()) {
        println!("{}", mat.as_str());
    }
}

struct AttachErr {
    ret: c_int,
    reason: String,
}

impl AttachErr {
    fn new(ret: c_int, str: String) -> AttachErr {
        AttachErr {
            ret,
            reason: str.to_string(),
        }
    }
}

impl fmt::Debug for AttachErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
            .field(&self.ret)
            .field(&self.reason)
            .finish()
    }
}

#[cfg(target_os = "linux")]
fn ptrace_attach(pid: pid_t) -> Result<pid_t, AttachErr> {
    unsafe {
        let data = ptr::null_mut::<c_char>();
        let ret = ptrace(PT_ATTACH, pid, data, 0);
        if ret == -1 {
            return Err(AttachErr::new(ret,
                                      format!("attach with ret:{}", ret)));
        }
        let mut status: c_int = 0;
        let ret = libc::waitpid(pid, &mut status, 0);
        if ret == -1 {
            return Err(AttachErr::new(ret,
                                      format!("waitpid with ret:{}", ret)));
        }
        let sig = WSTOPSIG(status);
        while !WIFSTOPPED(status) || sig != SIGSTOP {
            //如果在SIGSTOP之前收到其他信号，那么在接收之后要发送回去
            kill(pid, sig);
            libc::waitpid(pid, &mut status, 0);
        }
        return Ok(pid);
    }
}

#[cfg(target_os = "macos")]
fn ptrace_attach(pid: pid_t) -> Result<mach_port_t, String> {
    let r = mach_pt::mach_open_process(pid);
    return r;
}

#[cfg(target_os = "macos")]
fn ptrace_write_str(handle: mach_port_t, s: &str) -> Result<mach_vm_address_t, String> {
    let r = mach_pt::allocate_and_write_str(handle, s);
    return r;
}

extern "C" fn thread_routine(parg: *mut c_void) -> *mut c_void {
    unsafe {
        let content_cstr = str_to_cstr!("[thread] remote thread\n");
        libc::printf(content_cstr.as_ptr());
    }
    return ptr::null_mut::<c_void>();
}

fn get_thread_routine_addr()->mach_vm_address_t{
    let routine_addr:mach_vm_address_t = unsafe { std::mem::transmute(&thread_routine) };
    println!("routine_addr:0x{:x}",routine_addr);
    return routine_addr;
}


fn main() {
    let mut target_pid=getpid_rust();
    let mut lib_path="/Users/any/GolandProjects/macos-injector/test.dylib";
    let args: Vec<String>=env::args().collect();
    println!("args:{:?}",args);
    if args.len()>=2{
        target_pid= (&args[1]).parse().unwrap();
    }
    if args.len()>=3{
        lib_path=&args[2];
    }
    println!("target pid:{} lib path:{}",target_pid,lib_path);
    shell_code::test_shellcode();
    //计算函数偏移
    let libc_handle = get_libc_handle();
    println!(
        "[*] libc found at address {:p}", libc_handle
    );
    let local_malloc_addr = dlsym_rust(libc_handle, "malloc");
    println!(
        "[*] malloc found at address {:p}", local_malloc_addr
    );
    let local_dlopen_addr = dlsym_rust(libc_handle, "dlopen");
    println!(
        "[*] dlopen found at address {:p}", local_dlopen_addr
    );
    let local_pthread_create_from_mach_thread = dlsym_rust(libc_handle,
                                                           "pthread_create_from_mach_thread");
    println!(
        "[*] pthread_create_from_mach_thread found at address {:p}", local_pthread_create_from_mach_thread
    );
    //找到本地libc基址
    let self_pid = getpid_rust();
    let libc_base = get_libc_loadbase(self_pid);
    let dlopen_offset = (local_dlopen_addr as i64) - libc_base;
    println!("dlopen offset:{:x}", dlopen_offset);
    unsafe {
        let child_pid = fork_rust();
        if child_pid == 0 {
            //child process
            println!("[child] child pid:{}", getpid_rust());
            get_thread_routine_addr();
            let data = ptr::null_mut::<c_char>();
            //libc::ptrace(PT_TRACE_ME,0,data,0);
            //println!("[child] ptrace PT_TRACE_ME called");
            loop{

            }
        } else {
            println!("[parent] child_pid:{}", child_pid);
            let ret = ptrace_attach(target_pid);
            let mut handle = 0;
            match ret {
                Ok(handle_) => {
                    handle = handle_;
                }
                Err(err) => {
                    panic!("{:?}", err); //TODO
                }
            };
            println!("[parent] handle:{}", handle);
            //let handle=mach_task_self(); //TODO
            let mut path_address = 0;
            match ptrace_write_str(handle, lib_path) {
                Ok(path_addres_) => {
                    path_address = path_addres_;
                }
                Err(err) => {
                    panic!("{:?}", err);
                }
            }
            println!("[parent] path address:0x{:x}", path_address);
            let shellcode_vec = shell_code::shellcode(local_pthread_create_from_mach_thread as mach_vm_address_t,
                                                      0, local_dlopen_addr as mach_vm_address_t,
                                                      lib_path);
            let shellcode = shellcode_vec.as_slice();
            let shellcode_addr = mach_pt::allocate_and_write_data(handle,
                                                                  shellcode,
                                                                  VM_PROT_READ | VM_PROT_EXECUTE)
                .expect("TODO: panic message");
            println!("shellcode addr:{:x}", shellcode_addr);
            //allocate stack
            let stack_addr = mach_pt::allocate_stack(handle).unwrap();
            //init remote thread
            //thread_create_running
            let routine_addr=get_thread_routine_addr();
            let thread_args=[
                path_address,
                RTLD_NOW as u64,
                local_dlopen_addr as u64,
                local_pthread_create_from_mach_thread as u64,
            ];
            //stack addr should +1024 to let them use op sp- to extend stack size
            let thread_act = thread_state::thread_create_running_rust(handle,
                                                                      stack_addr+1024,
                                                                      shellcode_addr,thread_args.as_slice()).expect("TODO: panic message");
            println!("thread_act:{}", thread_act);
            loop {}
        }
    }
}
