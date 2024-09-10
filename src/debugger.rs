use debugrs::user_instructions::UserInstruction;
use nix::{errno::Errno, sys::ptrace};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use debugrs::{breakpoint::{Breakpoint, Context}, instruction_processor::{get_user_input, process_user_instruction}};

fn restore_breakpoint_if_needed(pid: Pid, context: &Context) -> Result<Option<&Breakpoint>, Errno> {
    let mut regs = ptrace::getregs(pid)?;
    let previous_rip = regs.rip - 1;
    match context.breakpoints.iter().find(|breakpoint| breakpoint.address == previous_rip) {
        Some(breakpoint) => {
            breakpoint.remove(pid)?;
            regs.rip = previous_rip;
            ptrace::setregs(pid, regs)?; // Restore rip as it was
            Ok(Some(breakpoint))
        }
        None => Ok(None)
    }
}

pub fn run(child: Pid) -> () {
    let _ = waitpid(child, None).expect("Failed to wait");
    println!("Process started");
    let mut context = Context::new();
    loop {
        match get_user_input() {
            Ok(user_instruction) => {
                process_user_instruction(child, &user_instruction, &mut context)
                    .unwrap_or_else(|err| println!("Encountered error: {err}"));

                match user_instruction {
                    UserInstruction::ContinueUntilBreakpoint
                    | UserInstruction::SingleStep
                    | UserInstruction::ContinueUntilSyscall => {}
                    _ => continue,
                };
                
                let wait_result = waitpid(child, None).expect("Failed to wait");
                match wait_result {
                    WaitStatus::Exited(child, status) => {
                        println!("Child {child} exited with status {status}, quitting...");
                        break;
                    },
                    WaitStatus::Stopped(_child, Signal::SIGTRAP) => {
                        context.remove_breakpoints(child); // Remove breakpoint so we can inspect memory without seeing them
                        // We need to check if we stopped on a breakpoint, and restore it in this case
                        let restored_breakpoint = restore_breakpoint_if_needed(child, &mut context)
                            .expect("Failed to check for breakpoints");
                        if let Some(breakpoint) = restored_breakpoint {
                            println!("Hit breakpoint at 0x{:x}", breakpoint.address)
                        }
                        continue;
                    },
                    wait_status => {
                        println!("{wait_status:?}");
                        continue
                    },
                }
            },
            Err(err) => println!("{err}")
        }
    }
}

