#![allow(dead_code)]

use std::{ffi::c_void, collections::HashMap};

use nix::{unistd, sys::ptrace, errno::Errno, sys::{wait, signal}};

pub struct AddrBreakpoint {
	addr: u64,
	replaced_word: Option<u64>
}

impl AddrBreakpoint {
	pub fn new(addr: u64) -> AddrBreakpoint {
		AddrBreakpoint {
			addr,
			replaced_word: None
		}
	}
}

pub enum Breakpoint {
	Syscall {
		syscall: i64
	},
	Addr(AddrBreakpoint)
}

#[derive(Debug)]
pub enum StopCause {
	Breakpoint(usize),
	UnknownBreakpoint,
	Exit {
		status: i32,
	},
	Signal {
		signal: signal::Signal,
		dumped: bool
	},
	Stopped {
		signal: signal::Signal,
	}
}

pub struct Tracer {
	child: unistd::Pid,
	breakpoints: Vec<Breakpoint>,
	break_on_syscall: bool,
	last_wait_status: Option<wait::WaitStatus>,
	awaiting_replacement: Vec<usize>
}

impl Tracer {
	pub unsafe fn from_pid(child: unistd::Pid) -> Tracer {
		Tracer {
			child,
			breakpoints: Vec::new(),
			break_on_syscall: false,
			last_wait_status: None,
			awaiting_replacement: Vec::new()
		}
	}

	pub fn attach(child: unistd::Pid) -> Result<Tracer, Errno> {
		ptrace::attach(child)?;
		wait::waitpid(child, None)?;

		Ok(unsafe { Tracer::from_pid(child) })
	}

	pub fn spawn(path: &str) -> Result<Tracer, Errno> {
		use std::ffi::CString;
	
		match unsafe { nix::unistd::fork() }? {
			unistd::ForkResult::Parent { child, .. } => {
				wait::waitpid(child, None)?;

				ptrace::setoptions(child, ptrace::Options::PTRACE_O_EXITKILL | ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

				Ok(unsafe { Tracer::from_pid(child) })
			},
			unistd::ForkResult::Child => {
				ptrace::traceme().expect("Could not traceme");

				// FIXME make this an option, not always on
				nix::sys::personality::set(nix::sys::personality::get().expect("Could not get personality") | nix::sys::personality::Persona::ADDR_NO_RANDOMIZE).expect("Could not set personality");
	
				let cstring = CString::new(path).unwrap();
				let err = nix::unistd::execv(&cstring, &[&cstring]).unwrap_err();
				eprintln!("Could not start - {}", err);
				std::process::exit(1);
			}
		}
	}

	pub fn pid(&self) -> i32 {
		self.child.as_raw()
	}

	fn drain_awaiting_replacements(&mut self) -> Result<(), Errno>  {
		let mut stepped = false;

		// FIXME This doesnt handle recently deleted breakpoints very well
		for awaiting_replacement in self.awaiting_replacement.drain(0..).collect::<Vec<usize>>() {
			match self.breakpoints.get(awaiting_replacement) {
				Some(Breakpoint::Addr(AddrBreakpoint { addr, replaced_word })) => {
					let addr = *addr;
					let replaced_word = replaced_word.unwrap();

					if !stepped {
						// FIXME what if the breakpoint is jmp $?
						ptrace::step(self.child, None)?;
						self.wait()?; // FIXME check this doesn't hit another breakpoint
						stepped = true;
					}

					self.write_u64(addr, (replaced_word & !0xff) | 0xcc)?;
				},
				// If None was just deleted, so fine to ignore
				_ => {}
			}
		}
		
		Ok(())
	}

	pub fn cont(&mut self) -> Result<(), Errno> {
		self.drain_awaiting_replacements()?;

		if self.break_on_syscall {
			ptrace::syscall(self.child, None)
		} else {
			ptrace::cont(self.child, None)
		}
	}

	pub fn detach(self) -> Result<(), Errno> {
		ptrace::detach(self.child, None)
	}

	pub fn wait(&mut self) -> Result<(), Errno> {
		self.last_wait_status = Some(wait::waitpid(self.child, None)?);
		Ok(())
	}

	pub fn step(&mut self) -> Result<(), Errno> {
		self.drain_awaiting_replacements()?;

		ptrace::step(self.child, None)
	}

	pub fn check_stop_cause(&mut self) -> Result<Option<StopCause>, Errno> {
		match self.last_wait_status {
			Some(wait::WaitStatus::Exited(_, status)) => Ok(Some(StopCause::Exit { status })),
			Some(wait::WaitStatus::Signaled(_, signal, dumped)) => Ok(Some(StopCause::Signal { signal, dumped })),
			Some(wait::WaitStatus::Stopped(_, signal)) => {
				match signal {
					nix::sys::signal::Signal::SIGTRAP => {
						let rip = self.rip()?;
						
						for (b, breakpoint) in self.breakpoints.iter().enumerate() {
							match breakpoint {
								Breakpoint::Addr(AddrBreakpoint { addr, replaced_word }) if *addr == rip - 1 => {
									self.write_u64(*addr, replaced_word.unwrap())?;
									self.awaiting_replacement.push(b);
									self.set_rip(rip - 1)?;

									return Ok(Some(StopCause::Breakpoint(b)));
								},
								_ => {},
							}
						}

						Ok(Some(StopCause::UnknownBreakpoint))
					},
					_ => Ok(Some(StopCause::Stopped { signal }))
				}
			},
			Some(wait::WaitStatus::PtraceEvent(_, _, _)) => todo!(),
			Some(wait::WaitStatus::PtraceSyscall(_)) => {
				assert!(self.break_on_syscall);
				let number = self.regs()?.orig_rax as i64;

				for (b, breakpoint) in self.breakpoints.iter().enumerate() {
					match breakpoint {
						Breakpoint::Syscall { syscall } if *syscall == number => {
							return Ok(Some(StopCause::Breakpoint(b)));
						},
						_ => {},
					}
				}
				
				// TODO: Probably just continue here?
				Ok(None)
			},
			Some(wait::WaitStatus::Continued(_)) => todo!(),
			Some(wait::WaitStatus::StillAlive) => todo!(),
			None => Ok(None)
		}
	}

	pub fn next(&mut self) -> Result<Option<StopCause>, Errno> {
		self.cont()?;
		self.wait()?;

		self.check_stop_cause()
	}

	pub fn cont_until(&mut self, breakpoint: usize) -> Result<StopCause, Errno> {
		loop {
			let cause = self.next()?;
			match &cause {
				Some(StopCause::Exit { .. }) | Some(StopCause::Signal { .. }) | Some(StopCause::Stopped { .. }) | Some(StopCause::UnknownBreakpoint) => {
					return Ok(cause.unwrap());
				},
				Some(StopCause::Breakpoint(idx)) => {
					if *idx == breakpoint {
						return Ok(cause.unwrap())
					}
				},
				None => {},
			}
		}
	}

	pub fn cont_until_end(&mut self) -> Result<StopCause, Errno> {
		loop {
			let cause = self.next()?;
			match &cause {
				Some(StopCause::Exit { .. }) => {
					return Ok(cause.unwrap());
				},
				_ => {},
			}
		}
	}

	pub fn regs(&self) -> Result<nix::libc::user_regs_struct, Errno> {
		ptrace::getregs(self.child)
	}

	pub fn rip(&self) -> Result<u64, Errno> {
		let regs = ptrace::getregs(self.child)?;
		Ok(regs.rip)
	}

	pub fn rsp(&self) -> Result<u64, Errno> {
		let regs = ptrace::getregs(self.child)?;
		Ok(regs.rsp)
	}

	pub fn set_rip(&mut self, rip: u64) -> Result<(), Errno> {
		let mut regs = ptrace::getregs(self.child)?;
		regs.rip = rip;
		ptrace::setregs(self.child, regs)
	}

	pub fn read_u64(&self, addr: u64) -> Result<u64, Errno> {
		Ok(ptrace::read(self.child, addr as *mut c_void)? as u64)
	}

	pub fn write_u64(&self, addr: u64, data: u64) -> Result<(), Errno> {
		unsafe { ptrace::write(self.child, addr as *mut c_void, data as *mut c_void) }
	}

	pub fn add_breakpoint(&mut self, mut breakpoint: Breakpoint) -> Result<usize, Errno> {
		match &mut breakpoint {
			Breakpoint::Addr(addr) => {
				let mut replaced = self.read_u64(addr.addr)?;
				addr.replaced_word = Some(replaced);
				replaced = (replaced & !0xff) | 0xcc; // breakpoint trap
				self.write_u64(addr.addr, replaced)?;
				
			},
			Breakpoint::Syscall { .. } => {
				self.break_on_syscall = true;
			},
		}

		self.breakpoints.push(breakpoint);
		Ok(self.breakpoints.len() - 1)
	}

	// FIXME This will mess up indices
	pub fn remove_breakpoint(&mut self, index: usize) -> Result<(), Errno> {
		match &self.breakpoints[index] {
			Breakpoint::Addr(addr) => {
				self.write_u64(addr.addr, addr.replaced_word.unwrap())?;
			},
			Breakpoint::Syscall { .. } => {
				self.break_on_syscall = false;
				
				for (b, breakpoint) in self.breakpoints.iter().enumerate() {
					if b != index && matches!(breakpoint, Breakpoint::Syscall { .. }) {
						self.break_on_syscall = true;
						break;
					}
				}
			},
		}
		self.breakpoints.remove(index);
		Ok(())
	}

	// NOTE Could also use /dev/{}/mem
	pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<(), Errno> {
		let m = data.len() as u64 % 8;
			
		for i in (0..data.len() - m as usize).step_by(8) {
			let num = self.read_u64(addr + i as u64)?;
			data[i..i + 8].copy_from_slice(&num.to_ne_bytes());
		}

		if m != 0 {
			let num = self.read_u64(addr + data.len() as u64 - m)?;
			let bytes = num.to_ne_bytes();
			let i = data.len() - m as usize;
			data[i..].copy_from_slice(&bytes[0..m as usize]);
		}

		Ok(())
	}

	// NOTE Could also use /dev/{}/mem
	pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
		let m = data.len() as u64 % 8;
			
		for i in (0..data.len() - m as usize).step_by(8) {
			self.write_u64(addr + i as u64, u64::from_ne_bytes(data[i..i + 8].try_into().unwrap()))?;
		}

		if m != 0 {
			let mut extended = self.read_u64(addr + data.len() as u64 - m)?.to_ne_bytes();
			for i in 0..m as usize {
				extended[i] = data[i + data.len() - m as usize];
			}
			self.write_u64(addr + data.len() as u64 - m, u64::from_ne_bytes(extended))?;
		}

		Ok(())
	}

	pub fn read_null_terminated(&mut self, addr: u64) -> Result<Vec<u8>, Errno> {
		let mut data = Vec::new();
		
		'stop: loop {
			let num = self.read_u64(addr + data.len() as u64)?.to_ne_bytes();
			
			for n in num {
				if n == 0 { break 'stop; }
				data.push(n);
			}
		}

		Ok(data)
	}

	// FIXME not only is the end address wrong, this API also misses out on a lot on interesting information - namely permissions
	pub fn maps(&self) -> Result<HashMap<String, (u64, u64)>, std::io::Error> {
		let path = format!("/proc/{}/maps", self.child);
		let maps = std::fs::read_to_string(path)?;

		let mut map = HashMap::new();

		for line in maps.lines() {
			let chunks = line.split_ascii_whitespace().collect::<Vec<&str>>();

			let range = chunks[0].split_once('-').unwrap();
			let range = (u64::from_str_radix(range.0, 16).unwrap(), u64::from_str_radix(range.1, 16).unwrap());

			if chunks[2] != "00000000" { continue }

			if let Some(name) = chunks.get(5) {
				map.insert((*name).to_owned(), range);
			}
		}

		Ok(map)
	}

	pub fn kill(&mut self) -> Result<(), Errno> {
		nix::sys::signal::kill(self.child, signal::SIGKILL)
	}
}