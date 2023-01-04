#[allow(unused_imports)]
#[macro_use]
extern crate ctor;

#[ctor]
fn main() {
    println!("Hello from dylib");
    let self_pid=unsafe{libc::getpid()};
    println!("[dylib] pid:{}",self_pid);

}