use libc::{__darwin_arm_thread_state64, mach_port_t, mach_vm_address_t};
use mach::message::mach_msg_type_number_t;
use mach::thread_status::{thread_state_flavor_t, thread_state_t};

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
pub struct x86_thread_state64_t {
    pub __rax: u64,
    pub __rbx: u64,
    pub __rcx: u64,
    pub __rdx: u64,
    pub __rdi: u64,
    pub __rsi: u64,
    pub __rbp: u64,
    pub __rsp: u64,
    pub __r8: u64,
    pub __r9: u64,
    pub __r10: u64,
    pub __r11: u64,
    pub __r12: u64,
    pub __r13: u64,
    pub __r14: u64,
    pub __r15: u64,
    pub __rip: u64,
    pub __rflags: u64,
    pub __cs: u64,
    pub __fs: u64,
    pub __gs: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct arm_thread_state64_t {
    pub __x: [u64; 29],
    pub __fp: u64,
    pub __lr: u64,
    pub __sp: u64,
    pub __pc: u64,
    pub __cpsr: u32,
    pub __pad: u32,
}

impl arm_thread_state64_t {
    fn new(stack_addr:mach_vm_address_t,routine_addr:mach_vm_address_t)->arm_thread_state64_t{
        let arr: [u64; 29] = [0; 29];
        let thread_state=arm_thread_state64_t{
            __x: arr,
            __fp: 0,
            __lr: 0,
            __sp: stack_addr,
            __pc: routine_addr,
            __cpsr: 0,
            __pad: 0,
        };
        return thread_state;
    }
}

const ARM_THREAD_STATE64:thread_state_flavor_t=6;

extern "C" {
    #[cfg(target_arch = "aarch64")]
    pub fn thread_create_running(remote_task:mach_port_t, flavor:thread_state_flavor_t,
                                 new_state:* const arm_thread_state64_t, new_state_cnt:mach_msg_type_number_t,
                                 child_act:* mut mach_port_t)-> i32;
    #[cfg(target_arch = "aarch64")]
    pub fn thread_get_state(
        target_act: mach_port_t,
        flavor: thread_state_flavor_t,
        new_state: *mut arm_thread_state64_t,
        new_state_count: *mut mach_msg_type_number_t,
    ) -> i32;
}
//kern_return_t thread_create_running(task_t parent_task, thread_state_flavor_t flavor, thread_state_t new_state, mach_msg_type_number_t new_stateCnt, thread_act_t *child_act);
pub fn thread_create_running_rust(remote_task:mach_port_t,stack_addr:mach_vm_address_t,
                                  routine_addr:mach_vm_address_t,
                                  args:&[u64])->Result<mach_port_t,String>{
    let mut arr: [u64; 29] = [0; 29];
    for i in 0..args.len(){
        arr[i]=args[i];
    }
    let thread_state=arm_thread_state64_t{
        __x: arr,
        __fp: 0,
        __lr: 0,
        __sp: stack_addr,
        __pc: routine_addr,
        __cpsr: 0,
        __pad: 0,
    };
    const ARM_THREAD_STATE64_COUNT: mach_msg_type_number_t = (core::mem::size_of::<arm_thread_state64_t>() / 4)
        as mach_msg_type_number_t;
    let state_param=&thread_state;
    let mut child_act=0;
    unsafe {
        let ret= thread_create_running(remote_task, ARM_THREAD_STATE64,
                              state_param, ARM_THREAD_STATE64_COUNT, &mut child_act);
        if ret!=0{
          return Err(format!("failed to create thread:{}",ret).to_owned());
        }
    }
    return Ok(child_act);
}

// pub fn get_thread_state_rust(thread_act:mach_port_t,){
//     let p_thread_state=&arm_thread_state64_t::new();
//     let mut new_state_count=0;
//     unsafe {
//         thread_get_state(thread_act, ARM_THREAD_STATE64, p_thread_state, &mut new_state_count);
//     }
// }

