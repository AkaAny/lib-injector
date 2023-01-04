use std::ffi::{c_char, c_int, c_void, CStr};
use libc::{mach_port_t, mach_task_self, mach_vm_address_t, mach_vm_size_t, pid_t, task_create, task_for_pid, task_t, VM_PROT_READ, vm_prot_t, VM_PROT_WRITE};

extern "C" {
    pub fn mach_vm_allocate(target_task: task_t,
                            address: *mut mach_vm_address_t, size: mach_vm_size_t,
                            flags: i32) -> i32;
    pub fn mach_vm_protect(target_task: task_t,
                           address: mach_vm_address_t, size: mach_vm_size_t,
                           set_maximum: i32,
                           new_protection: i32) -> i32;
    pub fn mach_vm_write(target_task: mach_port_t,
                     address: mach_vm_address_t,
                     data: *const c_char, data_count: mach_vm_size_t) -> c_int;
}

pub fn mach_open_process(pid:pid_t) -> Result<mach_port_t,String>{
    unsafe {
        let self_task = mach_task_self();
        let mut remote_task = 0;
        let ret = task_for_pid(self_task, pid, &mut remote_task);
        if ret == 5 {
            return Err("permission denied, u may need to be added into procmon group".parse().unwrap())
        }
        return Ok(remote_task);
    }
}

pub fn allocate_stack(remote_task:mach_port_t) ->Result<mach_vm_address_t,String>{
    const STACK_SIZE:mach_vm_size_t=65536;
    let mut target_address=0;
    unsafe {
        let ret=mach_vm_allocate(remote_task, &mut target_address, STACK_SIZE, 1);
        if ret!=0 {
            return Err(format!("failed to allocate stack with ret:{}",ret).to_owned())
        }
        println!("allocated len:{} target_address:{:x}",STACK_SIZE,target_address);
    }
    return Ok(target_address);
}

pub fn allocate_and_write_str(remote_task:mach_port_t,s:&str)->Result<mach_vm_address_t,String>{
    unsafe {
        let m=format!("{}\0",s);
        let data=m.as_bytes();
        let r=allocate_and_write_data(remote_task,data,VM_PROT_READ|VM_PROT_WRITE);
        return r;
    }
}

pub fn allocate_and_write_data(remote_task:mach_port_t,data:&[u8],perm:vm_prot_t)->Result<mach_vm_address_t,String>{
    unsafe {
        let m_len=data.len() as mach_vm_size_t;
        let mut target_address=0;
        mach_vm_allocate(remote_task, & mut target_address, m_len, 1);
        println!("allocated len:{} target_address:{:x}",m_len,target_address);
        //write
        let data_ptr=data.as_ptr() as *const c_char;
        mach_vm_write(remote_task,
                      target_address,
                      data_ptr,m_len);
        let ret=mach_vm_protect(remote_task,
                                target_address,m_len,
                                0,
                                perm); //rwx is not allowed(x flag will be stripped)
        if ret!=0{
            return Err(format!("failed to mprotect with ret:{}",ret).to_owned())
        }
        return Ok(target_address);
    }
}

pub fn create_remote_thread(handle:mach_port_t){

}
