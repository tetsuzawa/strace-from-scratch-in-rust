use std::{error::Error, result::Result};

const MAX_SYSCALLS: i32 = 303;

pub trait SyscallCounter {
    fn new() -> Self;
    fn inc(&mut self, syscall_id: i32) -> Result<(), Box<dyn Error>>;
}

impl SyscallCounter for Vec<u64> {
    fn new() -> Self {
        let s = vec![0; MAX_SYSCALLS as usize];
        return s;
    }

    fn inc(&mut self, syscall_id: i32) -> Result<(), Box<dyn Error>> {
        if syscall_id > MAX_SYSCALLS {
            return Err(format!("invalid syscall ID: {}", syscall_id).into());
        }
        self[syscall_id as usize] += 1;
        Ok(())
    }
}
