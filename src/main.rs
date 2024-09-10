use std::env;
use std::ffi::{CStr, CString};
use nix::sys::ptrace;
use nix::unistd::{fork, ForkResult};
mod debugger;

fn main() {
    let args: Vec<String> = env::args().collect();

    let exec_path = &args[1];

    let fork_result = unsafe { fork() }.expect("Failed to fork");
    match fork_result {
        ForkResult::Parent { child } => {
            debugger::run(child);
        }
        ForkResult::Child => {
            ptrace::traceme().expect("Failed to call traceme in child");
            let path: &CStr = &CString::new(exec_path.as_str()).unwrap();
            nix::unistd::execve::<&CStr, &CStr>(path, &[], &[]).unwrap();
            unreachable!("Execve should have replaced the program");
        }
    }
}