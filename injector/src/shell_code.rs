use std::arch::asm;
use std::borrow::Borrow;
use libc::{mach_vm_address_t, memcmp};

macro_rules! change_vec_value_without_grow {
    ($vec:ident,$pos:expr,$new_value:expr) => {
        for i in 0..$new_value.len(){
            $vec[$pos+i]=$new_value[i];
        }
    };
}

#[cfg(target_arch = "aarch64")]
pub fn shellcode(pthread_create_from_mach_thread_addr:mach_vm_address_t,
                 pthread_exit_addr:mach_vm_address_t,
                 dlopen_addr:mach_vm_address_t, lib_path:&str) -> Vec<u8> {
    let mut s_vec:Vec<u8>={
        Vec::from([
            //0000000000000000 <ltmp0>:
            0xe0,0x03,0x00,0x91, //+0:       mov     x0, sp
            0x00,0x40,0x00,0xd1, //+4:       sub     x0, x0, #16
            0xe1,0x03,0x1f,0xaa, //+8:       mov     x1, xzr
            0xe3,0x03,0x1f,0xaa, //+c:       mov     x3, xzr
            0xc4,0x00,0x00,0x10, //+10:       adr     x4, #24
            0x22,0x01,0x00,0x10, //+14:       adr     x2, #36
            0x85,0x00,0x40,0xf9, //+18:       ldr     x5, [x4]
            0xa0,0x00,0x3f,0xd6, //+1c:       blr     x5

//0000000000000020 <_loop>:
            0x07,0x00,0x00,0x10, //+20:       adr     x7, #0
            0xe0,0x00,0x1f,0xd6, //+24:       br      x7

//0000000000000028 <pthrdcrt>:
            0x50,0x54,0x48,0x52, //+28:       <unknown>
            0x44,0x43,0x52,0x54, //+2c:       b.mi    0xa4894 <lib+0xa4840>

//0000000000000030 <dlllopen>:
            0x44,0x4c,0x4f,0x50, //+30:       adr     x4, #649610
            0x45,0x4e,0x5f,0x5f, //+34:       <unknown>

//0000000000000038 <_thread>:
            0x21,0x00,0x80,0xd2, //+38:       mov     x1, #1
            0xc0,0x00,0x00,0x10, //+3c:       adr     x0, #24
            0x87,0xff,0xff,0x10, //+40:       adr     x7, #-16
            0xe8,0x00,0x40,0xf9, //+44:       ldr     x8, [x7]
            0x00,0x01,0x3f,0xd6, //+48:       blr     x8

//000000000000004c <_thread_loop>:
            0x07,0x00,0x00,0x10, //+4c:       adr     x7, #0
            0xe0,0x00,0x1f,0xd6, //+50:       br      x7

//0000000000000054 <lib>:
            0x4c,0x49,0x42,0x4c, //+54:       <unknown>
            0x49,0x42,0x4c,0x49, //+58:       <unknown>
            0x42,0x4c,0x49,0x42, //+5c:       <unknown>
            0x4c,0x49,0x42,0x4c, //+60:       <unknown>
            0x49,0x42,0x4c,0x49, //+64:       <unknown>
            0x42,0x4c,0x49,0x42, //+68:       <unknown>
            0x4c,0x49,0x42,0x4c, //+6c:       <unknown>
            0x49,0x42,0x4c,0x49, //+70:       <unknown>
            0x42,0x4c,0x49,0x42, //+74:       <unknown>
            0x4c,0x49,0x42,0x4c, //+78:       <unknown>
            0x49,0x42,0x4c,0x49, //+7c:       <unknown>
            0x42,0x4c,0x49,0x42, //+80:       <unknown>
            0x4c,0x49,0x42,0x4c, //+84:       <unknown>
            0x49,0x42,0x4c,0x49, //+88:       <unknown>
            0x42,0x4c,0x49,0x42, //+8c:       <unknown>
            0x4c,0x49,0x42,0x4c, //+90:       <unknown>
            0x49,0x42,0x4c,0x49, //+94:       <unknown>
            0x42,0x4c,0x49,0x42, //+98:       <unknown>
            0x4c,0x49,0x42,0x4c, //+9c:       <unknown>
            0x49,0x42,0x4c,0x49, //+a0:       <unknown>
            0x42,0x4c,0x49,0x42, //+a4:       <unknown>
        ])
    };
    println!("len of s_vec:{}",s_vec.len());
    let sub= "PTHRDCRT".as_bytes();
    let pos=find_substring(&s_vec,sub).unwrap();
    println!("pthread_create pos:{}",pos);
    let arr: [u8; 8] = unsafe { std::mem::transmute(pthread_create_from_mach_thread_addr) };
    change_vec_value_without_grow!(s_vec,pos,Vec::from(arr));
    //dlopen
    let sub="DLOPEN__".as_bytes();
    let pos=find_substring(&s_vec,sub).unwrap();
    println!("dlopen pos:{}",pos);
    let arr: [u8; 8] = unsafe { std::mem::transmute(dlopen_addr) };
    change_vec_value_without_grow!(s_vec,pos,Vec::from(arr));
    //lib path
    let sub="LIBLIBLIB".as_bytes();
    let pos=find_substring(&s_vec,sub).unwrap();
    println!("lib_path pos:{}",pos);
    let new_sub_str=lib_path.as_bytes();
    let mut lib_path_vec=Vec::from(lib_path);
    lib_path_vec.append(&mut Vec::from("\0"));
    change_vec_value_without_grow!(s_vec,pos,lib_path_vec);
    let s= s_vec;
    println!("s_vec ptr:{:p}",&s.as_ptr());
    return s;
}

pub fn test_shellcode(){
    let mut s_vec=vec!['t','h','i','s'];
    let sub=vec!['i'].to_vec();
    let pos=find_substring(&s_vec,sub.as_slice()).unwrap();
    println!("pos:{}",pos);
    let new_value=vec!['a','b'];
    // for i in 0..new_value.len()-1{
    //     s_vec[pos+i]=new_value[i];
    // }
    change_vec_value_without_grow!(s_vec,pos,new_value);
    println!("{:?}",s_vec.as_ptr());
}

fn get_subset<T:Clone>(vec: &Vec<T>, i: usize, n: usize) -> Option<Vec<T>> {
    if i + n > vec.len() {
        return None;
    }
    Some(vec[i..i+n].to_vec())
}

fn find_substring<T:PartialEq+Clone>(vec: &Vec<T>, target: &[T]) -> Option<usize> {
    for i in 0..vec.len(){
        let subset= get_subset(vec,i,target.len()).expect("out of range");
        if subset==target{
            return Some(i);
        }
    }
    return None;
}
