use std::iter::Peekable;

use trace::debugger;

use crate::{ErrAction, pretty_print_err, alive_debugger};

pub fn register_value(debugger: &debugger::Debugger, name: &str) -> Option<u64> {
    let regs = match debugger.regs() {
        Ok(regs) => regs,
        Err(err) => {
            pretty_print_err(err, "Could load registers", ErrAction::Nothing);
            return None;
        }
    };
    
    let (value, bits, high) = match name {
        "rax" => (regs.rax, 64, false), "eax" => (regs.rax, 32, false), "ax" => (regs.rax, 16, false), "al" => (regs.rax, 8, false), "ah" => (regs.rax, 8, true),
        "rcx" => (regs.rcx, 64, false), "ecx" => (regs.rcx, 32, false), "cx" => (regs.rcx, 16, false), "cl" => (regs.rcx, 8, false), "ch" => (regs.rcx, 8, true),
        "rdx" => (regs.rdx, 64, false), "edx" => (regs.rdx, 32, false), "dx" => (regs.rdx, 16, false), "dl" => (regs.rdx, 8, false), "dh" => (regs.rdx, 8, true),
        "rbx" => (regs.rbx, 64, false), "ebx" => (regs.rbx, 32, false), "bx" => (regs.rbx, 16, false), "bl" => (regs.rbx, 8, false), "bh" => (regs.rbx, 8, true),
        
        "rsi" => (regs.rsi, 64, false), "esi" => (regs.rsi, 32, false), "si" => (regs.rsi, 16, false), "sil" => (regs.rsi, 8, false),
        "rdi" => (regs.rdi, 64, false), "edi" => (regs.rdi, 32, false), "di" => (regs.rdi, 16, false), "dil" => (regs.rdi, 8, false),

        "rbp" => (regs.rbp, 64, false), "ebp" => (regs.rbp, 32, false), "bp" => (regs.rbp, 16, false), "bpl" => (regs.rbp, 8, false),
        "rsp" => (regs.rsp, 64, false), "esp" => (regs.rsp, 32, false), "sp" => (regs.rsp, 16, false), "spl" => (regs.rsp, 8, false),

        "rip" => (regs.rip, 64, false), "eip" => (regs.rip, 32, false), "ip" => (regs.rip, 16, false),

        "r8" => (regs.r8, 64, false), "r8d" => (regs.r8, 32, false), "r8w" => (regs.r8, 16, false), "r8b" => (regs.r8, 8, false),
        "r9" => (regs.r9, 64, false), "r9d" => (regs.r9, 32, false), "r9w" => (regs.r9, 16, false), "r9b" => (regs.r9, 8, false),
        "r10" => (regs.r10, 64, false), "r10d" => (regs.r10, 32, false), "r10w" => (regs.r10, 16, false), "r10b" => (regs.r10, 8, false),
        "r11" => (regs.r11, 64, false), "r11d" => (regs.r11, 32, false), "r11w" => (regs.r11, 16, false), "r11b" => (regs.r11, 8, false),
        "r12" => (regs.r12, 64, false), "r12d" => (regs.r12, 32, false), "r12w" => (regs.r12, 16, false), "r12b" => (regs.r12, 8, false),
        "r13" => (regs.r13, 64, false), "r13d" => (regs.r13, 32, false), "r13w" => (regs.r13, 16, false), "r13b" => (regs.r13, 8, false),
        "r14" => (regs.r14, 64, false), "r14d" => (regs.r14, 32, false), "r14w" => (regs.r14, 16, false), "r14b" => (regs.r14, 8, false),
        "r15" => (regs.r15, 64, false), "r15d" => (regs.r15, 32, false), "r15w" => (regs.r15, 16, false), "r15b" => (regs.r15, 8, false),

        _ => return None
    };

    Some(match bits {
        64 => value,
        32 => value & 0xffffffff,
        16 => value & 0xffff,
        8 if !high => value & 0xff,
        8 if high => (value >> 8) & 0xff,
        _ => unreachable!()
    })
}

pub fn parse_term(debugger: &Option<debugger::Debugger>, location: &mut Peekable<std::str::Chars>) -> Option<u64> {
	if location.peek()?.is_ascii_alphabetic() || *location.peek()? == '_' {
		let mut name = location.next().unwrap().to_string();

		while let Some(chr) = location.peek() {
			if !chr.is_ascii_alphabetic() && *chr != '_' { break }

			name.push(*chr);
			location.next();
		}

		let debugger = alive_debugger!(debugger, {
			return None;
		});

		match debugger.sym(&name) {
			Ok(addr) => Some(addr),
			Err(err) => match err {
				debugger::DebuggerError::NoSymbol(_) => {
					if let Some(register) = register_value(&debugger, &name) {
						Some(register)
					} else {
						pretty_print_err(err, "Could not load symbol", ErrAction::Nothing);
						None
					}
				},
				_ => {
					pretty_print_err(err, "Could not load symbol", ErrAction::Nothing);
					None
				}
			}
		}
	} else if *location.peek()? == '$' {
		let mut name = location.next().unwrap().to_string();

		while let Some(chr) = location.peek() {
			if !chr.is_ascii_alphabetic() && *chr != '_' { break }

			name.push(*chr);
			location.next();
		}

		let debugger = alive_debugger!(debugger, {
			return None;
		});

		if let Some(register) = register_value(&debugger, &name) {
			Some(register)
		} else {
			eprintln!("Unknown register {}", &name);
			None
		}
	} else if location.peek()?.is_ascii_digit() {
		if *location.peek().unwrap() == '0' {
			location.next();

			if *location.peek().unwrap() == 'x' {
				location.next();
				let mut num = String::new();

				while let Some(chr) = location.peek() {
					if !chr.is_ascii_hexdigit() { break }
	
					num.push(*chr);
					location.next();
				}
	
				return Some(u64::from_str_radix(&num, 16).unwrap())
			}
		}
		
		let mut num = location.next().unwrap().to_string();

		while let Some(chr) = location.peek() {
			if !chr.is_ascii_digit() { break }

			num.push(*chr);
			location.next();
		}

		Some(num.parse().unwrap())
	} else {
		None
	}
}

pub fn parse_expr(debugger: &mut Option<debugger::Debugger>, location: &mut Peekable<std::str::Chars>) -> Option<u64> {
	// FIXME don't always do this
    match debugger {
		Some(debugger) if debugger.is_alive() => {
			match debugger.refresh_maps() {
				Ok(_) => {},
				Err(err) => {
					pretty_print_err(err, "Could not refresh symbol maps", ErrAction::Nothing);
					return None;
				}
			}
		},
		_ => {}
	}

    let mut addr = parse_term(debugger, location)?;

    while let Some(chr) = location.peek() {
		let chr = *chr;

        match chr {
            '+' | '-' | '*' | '/' => {
                location.next();
                let rhs = parse_term(debugger, location)?;
                
                addr = match chr {
                    '+' => addr + rhs,
                    '-' => addr - rhs,
                    '*' => addr * rhs,
                    '/' => addr / rhs,
                    _ => unreachable!()
                };
            },
            _ => {
                break;
            }
        }
    }

    Some(addr)
}
