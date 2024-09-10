use nix::{errno::Errno, sys::ptrace::{self, AddressType}, unistd::Pid};

pub struct Breakpoint {
    pub address: u64,
    pub previous_byte: i8,
}

impl Breakpoint {
    pub fn insert(&self, pid: Pid) -> Result<(), Errno> {
        let Self {
            address,
            ..
        } = *self;
        let current_word = ptrace::read(pid, address as AddressType)?;
        let word_to_write = (current_word & !0xff) | 0xcc;
        unsafe { ptrace::write(pid, address as AddressType, word_to_write as AddressType) }?;
        Ok(())
    }

    pub fn remove(&self, pid: Pid) -> Result<(), Errno> {
        let Self {
            address,
            previous_byte,
        } = *self;
        let current_word = ptrace::read(pid, address as AddressType)?;
        let word_to_write = (current_word & !0xff) | (0xff & previous_byte as i64);
        unsafe { ptrace::write(pid, address as AddressType, word_to_write as AddressType) }?;
        Ok(())
    }
}

pub struct Context {
    pub breakpoints: Vec<Breakpoint>
}

impl Context{
    pub fn new() -> Self {
        Context {
            breakpoints: Vec::new(),
        }
    }

    pub fn add_breakpoint(&mut self, breakpoint: Breakpoint) {
        if self
            .breakpoints
            .iter()
            .find(|b| b.address == breakpoint.address)
            .is_none()
        {
            self.breakpoints.push(breakpoint)
        }
    }

    pub fn apply_breakpoints(&self, pid: Pid) {
        self.breakpoints
            .iter()
            .for_each(|breakpoint| breakpoint.insert(pid).unwrap())
    }
    pub fn remove_breakpoints(&self, pid: Pid) {
        self.breakpoints
            .iter()
            .for_each(|breakpoint| breakpoint.remove(pid).unwrap())
    }
}