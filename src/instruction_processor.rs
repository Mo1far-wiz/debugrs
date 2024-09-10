use std::{fs::File, io::{BufRead, BufReader, Write}, str::FromStr};

use thiserror::Error;
use nix::{errno::Errno, libc::user_regs_struct, sys::{ptrace::{self, AddressType}, wait::waitpid}, unistd::Pid};
use crate::{breakpoint::{Breakpoint, Context}, user_instructions::{UserInstruction, UserInstructionParseError}};

#[derive(Error, Debug)]
pub enum InputError {
    #[error("Invalid input")]
    InvalidInput,
    #[error("Could not parse instruction: {0}")]
    UserInstructionParseError(#[from] UserInstructionParseError),
}

const PREFIX: &'static str = "(drs)";


pub fn get_user_input() -> Result<UserInstruction, InputError> {
    use std::io::{stdin, stdout};
    print!("{PREFIX} ");
    let _ = stdout().flush();
    let mut raw_input = String::new();
    stdin().read_line(&mut raw_input).map_err(|_| InputError::InvalidInput)?;
    UserInstruction::from_str(&raw_input).map_err(InputError::UserInstructionParseError)
}


#[derive(Error, Debug)]
pub enum ProcessingError {
    #[error("Error using ptrace syscall: {0}")]
    Errno(#[from] Errno),
    #[error("No such value in process memory")]
    ValueNotFoundInMemory,
    #[error("Can't find stack memory adresses")]
    StackMemoryAddresesNotFound
}

pub fn process_user_instruction(pid : Pid, user_instruction : &UserInstruction, context: &mut Context) -> Result<(), ProcessingError> {
    match user_instruction {
        UserInstruction::ContinueUntilBreakpoint =>{
            ptrace::step(pid, None)?;
            let _ = waitpid(pid, None).expect("Failed to wait");
            context.apply_breakpoints(pid);
            ptrace::cont(pid, None)?;
        },
        UserInstruction::ContinueUntilSyscall => {
            ptrace::step(pid, None)?;
            let _ = waitpid(pid, None).expect("Failed to wait");
            context.apply_breakpoints(pid);
            ptrace::syscall(pid, None)?;
        },
        UserInstruction::ShowHelp => {
            println!("
            \tn : will mean Continue to next instruction (single-step)
            \th : will mean Display help
            \tm : will mean Display memory at the address specified in hex
            \tw : will mean Write decimal value to memory at the address specified in hex
            \tf : will mean Find decimal value in memory
            \tr : will stands for Show registers
            \tc : will be Continue until next breakpoint
            \ts : will be Continue until next syscall")
        },
        UserInstruction::ShowMemory { address } => {
            let value = ptrace::read(pid, *address as AddressType)?;
            println!("{value:#x}", value = value as i32);
        },
        UserInstruction::ShowRegisters => {
            let regs = UserRegsStruct(ptrace::getregs(pid)?);
            println!("{regs}");
        },
        UserInstruction::AddBreakpoint { address } => {
            let previous_word = ptrace::read(pid, *address as AddressType)?;
            let breakpoint = Breakpoint {
                address: *address,
                previous_byte: (previous_word & 0xff) as i8,
            };
            context.add_breakpoint(breakpoint);
        },
        UserInstruction::WriteToMemory { address, value } => {
            let _ = unsafe{ptrace::write(pid, *address as AddressType, *value as AddressType)?};
            println!("Write {value} to address {address:#014x}");
        },
        UserInstruction::FindInMemory { value } => {
            let value = *value as i32;
            let maps_file_path = File::open(format!("/proc/{}/maps", pid)).expect("Failed to open maps");
            let mut addresses : Vec<u64> = Vec::new();
            let mut stack_boundaries : Option<(u64, u64)> = None;
            let pointer_size = std::mem::size_of::<*const ()>();

            let reader = BufReader::new(maps_file_path);
            for line in reader.lines() {
                let line = line.expect("Error reading line in maps");
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.contains(&"[stack]") {
                    let addr_parts: Vec<&str> = parts[0].split("-").collect();
                    let stack_begin = u64::from_str_radix(addr_parts[0], 16).expect("Failed to extract stack begin address");
                    let stack_end = u64::from_str_radix(addr_parts[1], 16).expect("Failed to extract stack end address");
                    stack_boundaries = Some((stack_begin+pointer_size as u64, stack_end-pointer_size as u64));
                }
            }
            match stack_boundaries {
                None => {
                    return Err(ProcessingError::StackMemoryAddresesNotFound);
                },
                Some((b, e)) => {
                    for addr in (b..=e).step_by(pointer_size) {
                        let mem_value = ptrace::read(pid, addr as AddressType)?;
                        let mem_value = mem_value as i32;
                        if mem_value == value {
                            addresses.push(addr);
                        }
                    }
                }
            }

            if addresses.len() < 1 {
                return Err(ProcessingError::ValueNotFoundInMemory);
            }

            for addr in addresses {
                println!("{addr:#014x} => {value}");
            }
        },
        UserInstruction::SingleStep => ptrace::step(pid, None)?,
    };
    Ok(())
}

struct UserRegsStruct(user_regs_struct);

impl std::fmt::Display for UserRegsStruct {
   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let user_regs_struct {
            r15,
            r14,
            r13: _,
            r12: _,
            rbp: _,
            rbx: _,
            r11: _,
            r10: _,
            r9: _,
            r8: _,
            rax,
            rcx,
            rdx,
            rsi,
            rdi,
            orig_rax,
            rip,
            cs: _,
            eflags: _,
            rsp: _,
            ss: _,
            fs_base: _,
            gs_base: _,
            ds: _,
            es: _,
            fs: _,
            gs: _,
        } = self.0;
        write!(f, "rax: {rax}\norig_rax: {orig_rax:#X}\nrcx: {rcx}\nrdx: {rdx}\nrsi: {rsi}\nrdi: {rdi:#X}\nrip: {rip:#X}\nr15: {r15}\nr14: {r14:#X}")
    }
}
