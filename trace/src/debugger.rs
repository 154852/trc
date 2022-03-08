#![allow(dead_code)]

use std::{collections::HashMap, io::{Seek, Read}};

use crate::tracer::{AddrBreakpoint, Tracer, Breakpoint, StopCause};

pub struct Symbol {
    addr: u64,
	size: u64,
    file: String,
	name: String,
	pie: bool
}

impl Symbol {
    fn map(&self, map: &HashMap<String, (u64, u64)>) -> Result<u64, DebuggerError> {
		if self.pie {
			match map.get(&self.file) {
				Some(map) => Ok(map.0 + self.addr),
				None => Err(DebuggerError::NoMap(self.file.to_owned()))
			}
		} else {
			Ok(self.addr)
		}
    }

	fn load_from_elf(file: &elf::File, path: &str, pie: bool, symbols: &mut HashMap<String, Symbol>) -> Result<(), elf::ParseError> {
		for name in [".symtab", ".dynsym"] {
			if let Some(table) = file.get_section(name) {
				for symbol in file.get_symbols(table)? {
					if symbol.value != 0 {
						symbols.insert(symbol.name.clone(), Symbol {
							addr: symbol.value,
							size: symbol.size,
							file: path.to_owned(),
							name: symbol.name.clone(),
							pie
						});
					}
				}
			}
		}
	
		Ok(())
	}

	pub fn name(&self) -> &str {
		&self.name
	}
}

#[derive(Debug)]
pub enum DebuggerError {
	Nix(nix::errno::Errno),
	Io(std::io::Error),
	Parse(elf::ParseError),
	NoSymbol(String),
	NoMap(String),
}

pub struct CoreDump {
	registers: nix::libc::user_regs_struct
}

impl CoreDump {
	pub fn regs(&self) -> &nix::libc::user_regs_struct {
		&self.registers
	}
}

pub struct Debugger {
	tracer: Tracer,
	symbols: HashMap<String, Symbol>,
	maps: HashMap<String, (u64, u64)>,
	alive: bool,
	path: String
}

impl Debugger {
	pub fn load(root: &str) -> Result<Debugger, DebuggerError> {
		let tracer = match Tracer::spawn(root) {
			Ok(tracer) => tracer,
			Err(err) => return Err(DebuggerError::Nix(err)),
		};
		
		let maps = match tracer.maps() {
			Ok(maps) => maps,
			Err(err) => return Err(DebuggerError::Io(err))
		};

		let mut debugger = Debugger {
			tracer,
			symbols: HashMap::new(),
			maps,
			alive: true,
			path: root.to_string()
		};

		debugger.append_symbols_file(root)?;

		Ok(debugger)
	}

	pub fn load_core(&self, path: &str) -> Result<CoreDump, DebuggerError> {
		let elf = match elf::File::open_path(path) {
			Ok(elf) => elf,
			Err(err) => return Err(DebuggerError::Parse(err))
		};

		// FIXME This is quite ugly
		let mut file = match std::fs::File::open(path) {
			Ok(file) => file,
			Err(err) => return Err(DebuggerError::Io(err))
		};

		let mut registers = nix::libc::user_regs_struct {
			r15: 0, r14: 0, r13: 0, r12: 0,
			rbp: 0, rbx: 0, r11: 0, r10: 0,
			r9: 0, r8: 0, rax: 0, rcx: 0,
			rdx: 0, rsi: 0, rdi: 0, orig_rax: 0,
			rip: 0, cs: 0, eflags: 0, rsp: 0, ss: 0,
			fs_base: 0, gs_base: 0,
			ds: 0, es: 0, fs: 0, gs: 0,
		};

		for segment in elf.phdrs {
			if segment.progtype == elf::types::PT_NOTE {
				match file.seek(std::io::SeekFrom::Start(segment.offset)) {
					Ok(_) => {},
					Err(err) => return Err(DebuggerError::Io(err))
				}

				let mut data = vec![0; segment.filesz as usize];
				match file.read(&mut data) {
					Ok(_) => {}, // FIXME maybe don't assume this just works?
					Err(err) => return Err(DebuggerError::Io(err))
				}

				let mut idx = 0;
				while idx < segment.filesz as usize {
					let mut namesz = u32::from_ne_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
					let mut descsz = u32::from_ne_bytes(data[idx + 4..idx + 8].try_into().unwrap()) as usize;
					let type_ = u32::from_ne_bytes(data[idx + 8..idx + 12].try_into().unwrap());

					idx += 12;

					if namesz % 8 != 0 { namesz += 8 - (namesz % 8); }
					idx += namesz;

					match type_ {
						1 => { // NT_PRSTATUS
							let regs = &data[idx + 112..idx + 328];

							assert!(regs.len() == std::mem::size_of::<nix::libc::user_regs_struct>());
							
							unsafe {
								registers = *(regs.as_ptr() as *const nix::libc::user_regs_struct);
							}
						},
						_ => {}
					};

					if descsz % 8 != 0 { descsz += 8 - (descsz % 8); }
					
					idx += namesz + descsz;
				}
			}
		}

		Ok(CoreDump {
			registers
		})
	}

	pub fn pid(&self) -> i32 {
		self.tracer.pid()
	}

	pub fn append_symbols_file(&mut self, path: &str) -> Result<(), DebuggerError> {
		// FIXME This is a bit of a hack, but malloc is defined in both ld- and libc-, and we probably don't want symbols from ld- anyway.
		if path.starts_with("ld-") {
			return Ok(())
		}

		let mut path = std::path::PathBuf::from(path);
		if !path.exists() {
			let mut new_path = std::path::PathBuf::from("/usr/lib/x86_64-linux-gnu/");
			new_path.extend(&path);

			path = new_path;
		}

		path = match path.canonicalize() {
			Ok(path) => path,
			Err(err) => return Err(DebuggerError::Io(err))
		};

		let file = match elf::File::open_path(&path) {
			Ok(file) => file,
			Err(err) => return Err(DebuggerError::Parse(err))
		};

		let is_pie = match file.ehdr.elftype {
			elf::types::ET_NONE => false,
			elf::types::ET_CORE => false,
			elf::types::ET_DYN => true,
			elf::types::ET_EXEC => false,
			elf::types::ET_REL => true,
			_ => unreachable!()
		};

		if let Some(dynamic) = file.get_section(".dynamic") {
			if let Some(dynamic_strings) = file.get_section(".dynstr") {
				for i in (0..=dynamic.data.len() - 16).step_by(16) {
					let tag = u64::from_le_bytes(dynamic.data[i..i + 8].try_into().unwrap());
					let val_or_ptr = u64::from_le_bytes(dynamic.data[i + 8..i + 16].try_into().unwrap());

					if tag == 0x1 {
						// DT_NEEDED
						let needed_path = elf::utils::get_string(&dynamic_strings.data, val_or_ptr as usize).expect("Invalid path");
						self.append_symbols_file(&needed_path)?;
					}
					
					// else if tag == 0x000000006ffffffb && (val_or_ptr & 0b1) != 0 {
					// 	// FLAGS_1, pie
					// 	is_pie = true;
					// }
				}
			}
		}

		match Symbol::load_from_elf(&file, &path.display().to_string(), is_pie, &mut self.symbols) {
			Ok(_) => {},
			Err(err) => return Err(DebuggerError::Parse(err))
		}

		Ok(())
	}

	pub fn maps(&self) -> &HashMap<String, (u64, u64)> {
		&self.maps
	}

	pub fn refresh_maps(&mut self) -> Result<(), DebuggerError> {
		self.maps = match self.tracer.maps() {
			Ok(maps) => maps,
			Err(err) => return Err(DebuggerError::Io(err))
		};

		Ok(())
	}

	pub fn break_on_syscall(&mut self, syscall: i64) -> Result<usize, DebuggerError> {
		match self.tracer.add_breakpoint(Breakpoint::Syscall { syscall }) {
			Ok(idx) => Ok(idx),
			Err(err) => Err(DebuggerError::Nix(err))
		}
	}

	pub fn break_at(&mut self, addr: u64) -> Result<usize, DebuggerError> {
		match self.tracer.add_breakpoint(Breakpoint::Addr(AddrBreakpoint::new(
			addr
		))) {
			Ok(idx) => Ok(idx),
			Err(err) => Err(DebuggerError::Nix(err))
		}
	}

	pub fn skip_to(&mut self, addr: u64) -> Result<StopCause, DebuggerError> {
		let idx = match self.break_at(addr) {
			Ok(idx) => idx,
			Err(err) => return Err(err)
		};

		let stop_cause = match self.tracer.cont_until(idx) {
			Ok(cause) => cause,
			Err(err) => return Err(DebuggerError::Nix(err))
		};

		match &stop_cause {
			StopCause::Exit { .. } | StopCause::Signal { .. }  => self.alive = false,
			_ => {}
		}

		if self.alive {
			match self.tracer.remove_breakpoint(idx) {
				Ok(()) => {},
				Err(err) => return Err(DebuggerError::Nix(err))
			}
		}

		Ok(stop_cause)
	}

	pub fn skip_to_end(&mut self) -> Result<StopCause, DebuggerError> {
		match self.tracer.cont_until_end() {
			Ok(cause) => Ok(cause),
			Err(err) => return Err(DebuggerError::Nix(err))
		}
	}

	pub fn sym(&self, name: &str) -> Result<u64, DebuggerError> {
		match self.symbols.get(name) {
			Some(symbol) => symbol.map(&self.maps),
			None => Err(DebuggerError::NoSymbol(name.to_owned()))
		}
	}

	// Assumes that the stack pointer currently points to the return address
	pub fn finish_function(&mut self) -> Result<StopCause, DebuggerError> {
		let rsp = match self.tracer.rsp() {
			Ok(rsp) => rsp,
			Err(err) => return Err(DebuggerError::Nix(err))
		};

		let return_address = match self.tracer.read_u64(rsp) {
			Ok(addr) => addr,
			Err(err) => return Err(DebuggerError::Nix(err))
		};

		let return_breakpoint = match self.tracer.add_breakpoint(Breakpoint::Addr(AddrBreakpoint::new(
			return_address
		))) {
			Ok(idx) => idx,
			Err(err) => return Err(DebuggerError::Nix(err))
		};

		let cause = match self.tracer.cont_until(return_breakpoint) {
			Ok(cause) => cause,
			Err(err) => return Err(DebuggerError::Nix(err)),
		};

		match self.tracer.remove_breakpoint(return_breakpoint) {
			Ok(()) => {},
			Err(err) => return Err(DebuggerError::Nix(err)),
		}

		Ok(cause)
	}

	pub fn next(&mut self) -> Result<Option<StopCause>, DebuggerError> {
		match self.tracer.next() {
			Ok(cause) => {
				match &cause {
					Some(StopCause::Exit { .. }) | Some(StopCause::Signal { .. })  => self.alive = false,
					_ => {}
				}
				Ok(cause)
			},
			Err(err) => Err(DebuggerError::Nix(err)),
		}
	}

	pub fn regs(&self) -> Result<nix::libc::user_regs_struct, DebuggerError> {
		match self.tracer.regs() {
			Ok(regs) => Ok(regs),
			Err(err) => Err(DebuggerError::Nix(err)),
		}
	}

	pub fn read_u64(&mut self, addr: u64) -> Result<u64, DebuggerError> {
		match self.tracer.read_u64(addr) {
			Ok(n) => Ok(n),
			Err(err) => Err(DebuggerError::Nix(err)),
		}
	}

	pub fn read(&mut self, addr: u64, data: &mut [u8]) -> Result<(), DebuggerError> {
		match self.tracer.read(addr, data) {
			Ok(n) => Ok(n),
			Err(err) => Err(DebuggerError::Nix(err)),
		}
	}

	pub fn read_null_terminated(&mut self, addr: u64) -> Result<Vec<u8>, DebuggerError> {
		match self.tracer.read_null_terminated(addr) {
			Ok(vec) => Ok(vec),
			Err(err) => Err(DebuggerError::Nix(err)),
		}
	}

	pub fn step(&mut self) -> Result<Option<StopCause>, DebuggerError> {
		match self.tracer.step() {
			Ok(_) => {},
			Err(err) => return Err(DebuggerError::Nix(err)),
		}

		match self.tracer.wait() {
			Ok(_) => {},
			Err(err) => return Err(DebuggerError::Nix(err)),
		}

		match self.tracer.check_stop_cause() {
			Ok(cause) => Ok(cause),
			Err(err) => return Err(DebuggerError::Nix(err)),
		}
	}

	pub fn symbols(&self) -> &HashMap<String, Symbol> {
		&self.symbols
	}

	pub fn is_alive(&self) -> bool {
		self.alive
	}

	pub fn kill(&mut self) -> Result<(), DebuggerError> {
		match self.tracer.kill() {
			Ok(_) => Ok(()),
			Err(err) => Err(DebuggerError::Nix(err))
		}
	}

	pub fn path(&self) -> &str {
		&self.path
	}

	pub fn find_sym_for(&self, addr: u64) -> Result<Option<&Symbol>, DebuggerError> {
		// FIXME probably a way to do this faster than O(n)

		for symbol in self.symbols.values() {
			let sym_addr =  symbol.map(&self.maps)?;
			if addr >= sym_addr && addr < sym_addr + symbol.size {
				return Ok(Some(symbol));
			}
		}

		Ok(None)
	}
}
