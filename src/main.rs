extern crate libc;
extern crate nix;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
// use nix::sys::ptrace::attach;
// use nix::sys::ptrace::setoptions;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use strace_from_scratch_in_rust::SyscallCounter;

use std::env;
use std::error::Error;
use std::ops::Add;
use std::os::unix::prelude::CommandExt;
use std::process::Command;

const CMD_NAME: &'static str = "stracers";

fn main() {
    std::process::exit(match run() {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("{}: {}", CMD_NAME, err);
            1
        }
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err("not enough arguments".into());
    }
    stracers(&args[1], &args[2..])
}

fn stracers(program: &String, args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new(program);
    cmd.args(args.iter());
    unsafe {
        cmd.pre_exec(|| {
            println!("pre exec");
            ptrace::traceme().map_err(|e| match e {
                e => std::io::Error::from_raw_os_error(e as i32),
                _ => std::io::Error::new(std::io::ErrorKind::Other, "unknown PTRACE_TRACEME error"),
            })
        })
    };
    let child = cmd.spawn()?;
    let pid = Pid::from_raw(child.id() as i32);
    // match waitpid(Some(pid), None) {
    //     Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => (),
    //     _ => {
    //         return Err(
    //             std::io::Error::new(std::io::ErrorKind::Other, "Child state not correct").into(),
    //         )
    //     }
    // };
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXEC)?;
    ptrace::syscall(pid, None)?;

    let mut exit = true;
    let mut syscall_counter: Vec<u64> = SyscallCounter::new();

    loop {
        match waitpid(pid, None) {
            Err(e) => println!("{:?}", e),
            Ok(WaitStatus::Exited(pid, status)) => {
                println!("exit {} with status {}", pid, status);
                break;
            }
            Ok(WaitStatus::PtraceSyscall(_)) => {
                if exit {
                    let regs = ptrace::getregs(pid)?;
                    syscall_counter.inc(regs.orig_rax as i32)?;
                };
                exit = !exit;
            }
            _ => {}
        };

        ptrace::syscall(pid, None)?;
    }

    println!("{:?}", syscall_counter);
    Ok(())
}
