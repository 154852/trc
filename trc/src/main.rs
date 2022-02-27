use std::io::Write;

use clap::StructOpt;
use colored::Colorize;
use trace::{debugger, tracer};

mod cmd;
mod expr;

/// Program tracer
#[derive(clap::Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    file: Option<String>
}

enum ErrAction {
    Abort,
    Nothing
}

fn pretty_print_err<T: Into<String>>(err: debugger::DebuggerError, base: T, action: ErrAction) {
    eprint!("{} - ", base.into().red().bold());

    match err {
        debugger::DebuggerError::Nix(nix) => eprint!("ptrace error {}", nix),
        debugger::DebuggerError::Io(io) => eprint!("io error {}", io),
        debugger::DebuggerError::Parse(parse) => eprint!("elf parsing error {:?}", parse),
        debugger::DebuggerError::NoSymbol(name) => eprint!("symbol not found '{}'", name),
        debugger::DebuggerError::NoMap(path) => eprint!("mapping not found for '{}'", path),
    }

    match action {
        ErrAction::Abort => eprintln!(" - {}", "aborting".red().bold()),
        ErrAction::Nothing => eprintln!(),
    }
}

fn build_commands() -> cmd::CommandSet {
    cmd::CommandSet::new()
        .ns(
            cmd::Namespace::new('p', "Process")
                .cmd(cmd::Command::new('i', |dbg, _| cmd_process_pid(dbg)).describe("display process pid"))
                .cmd(cmd::Command::new('m', |dbg, _| cmd_process_maps(dbg)).describe("display process maps"))
                .cmd(cmd::Command::new('r', |dbg, _| cmd_process_restart(dbg)).describe("restart process"))
        )
        .cmd(
            cmd::Command::new('e', |dbg, parser| cmd_eval(dbg, parser)).describe("evaluate an expression").expr("expr")
        )
        .ns(
            cmd::Namespace::new('c', "Continue")
                .cmd(cmd::Command::new('n', |dbg, _| cmd_continue_next(dbg)).describe("continue until next event"))
                .cmd(cmd::Command::new('s', |dbg, _| cmd_continue_step(dbg)).describe("single step"))
                .cmd(cmd::Command::new('u', |dbg, parser| cmd_continue_until(dbg, parser)).describe("continue until address").expr("address"))
                .cmd(cmd::Command::new('f', |dbg, _| cmd_continue_finish(dbg)).describe("finish function"))
        )
        .ns(
            cmd::Namespace::new('m', "Memory")
                .cmd(cmd::Command::new('r', |dbg, parser| cmd_memory_read(dbg, parser)).describe("read from memory").op_type().num().expr("addr"))
                .cmd(cmd::Command::new('w', |_, _| todo!()).describe("write to memory").op_type().num().expr("addr").expr("value"))
        )
}

fn main() {
    let args = Args::parse();

    let commands = build_commands();

    let mut debugger = match args.file {
        Some(file) => match debugger::Debugger::load(&file) {
            Ok(debugger) => {
                eprintln!("{}", format!("- {} symbols loaded", debugger.symbols().len()).green().bold());
                eprintln!("{}", format!("- {} named regions mapped", debugger.maps().len()).green().bold());
                Some(debugger)
            },
            Err(err) => {
                pretty_print_err(err, format!("Could not load {}", file), ErrAction::Abort);
                std::process::exit(1);
            }
        },
        None => None
    };

    let stdin = std::io::stdin();
    loop {
        // TODO possibly also show the symbol and the map name
        if let Some(debugger) = &debugger {
            if debugger.is_alive() {
                match debugger.regs() {
                    Ok(regs) => print!("{}", format!("0x{:x} > ", regs.rip).cyan().bold()),
                    Err(err) => {
                        pretty_print_err(err, "Could not get program rip", ErrAction::Nothing);
                        print!("{}", " > ".cyan().bold());
                    }
                }
            } else {
                print!("{}", " > ".cyan().bold());
            }
        } else {
            print!("{}", " > ".cyan().bold());
        }

        match std::io::stdout().lock().flush() {
            Ok(_) => {},
            Err(_) => {}
        }
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(_) => {},
            Err(_) => break
        }
        let command = line.trim();

        commands.parse_and_exec(&mut debugger, command);
    }
}

#[macro_export]
macro_rules! alive_debugger {
    ($debugger:expr) => {
        match $debugger {
            Some(debugger) => {
                if debugger.is_alive() {
                    debugger
                } else {
                    eprintln!("Debugged process not alive");
                    return;
                }
            },
            None => {
                eprintln!("No debugging context running");
                return;
            }
        }
    };
    ($debugger:expr, $action:tt) => {
        match $debugger {
            Some(debugger) => {
                if debugger.is_alive() {
                    debugger
                } else {
                    eprintln!("Debugged process not alive");
                    $action
                }
            },
            None => {
                eprintln!("No debugging context running");
                $action
            }
        }
    };
}

#[macro_export]
macro_rules! present_debugger {
    ($debugger:expr) => {
        match $debugger {
            Some(debugger) => debugger,
            None => {
                eprintln!("No debugging context running");
                return;
            }
        }
    };
}


fn cmd_process_pid(debugger: &mut Option<debugger::Debugger>) {
    let debugger = present_debugger!(debugger);

    eprintln!("Currently tracing process {}", format!("{}", debugger.pid()).bold());
}

fn cmd_process_maps(debugger: &mut Option<debugger::Debugger>) {
    let debugger = present_debugger!(debugger);

    // Do not use debugger.maps, since this holds only very bare bones information
    let path = format!("/proc/{}/maps", debugger.pid());
    let maps = match std::fs::read_to_string(path) {
        Ok(maps) => maps,
        Err(err) => {
            pretty_print_err(debugger::DebuggerError::Io(err), "Could not load process maps", ErrAction::Nothing);
            return;
        }
    };

    for line in maps.lines() {
        let chunks = line.split_ascii_whitespace().collect::<Vec<&str>>();

        let range = chunks[0].split_once('-').unwrap();
        let range = (u64::from_str_radix(range.0, 16).unwrap(), u64::from_str_radix(range.1, 16).unwrap());

        let perms = format!(
            "{}{}{}",
            match chunks[1].chars().nth(0) {
                Some('r') => "r".blue(),
                _ => "-".black()
            },
            match chunks[1].chars().nth(1) {
                Some('w') => "w".green(),
                _ => "-".black()
            },
            match chunks[1].chars().nth(2) {
                Some('x') => "x".red(),
                _ => "-".black()
            },
        );

        let name = chunks.get(5);
        
        let offset = u64::from_str_radix(chunks[2], 16).unwrap();
        let offset = match name {
            None => format!("0x{:0>8x}", offset).black(),
            Some(name) => if name.starts_with('[') {
                format!("0x{:0>8x}", offset).black()
            } else {
                format!("0x{:0>8x}", offset).normal()
            },
        };

        let name = match name {
            None => None,
            Some(name) => Some(if name.starts_with('[') {
                name.bold()
            } else {
                name.normal()
            })
        };

        match name {
            Some(name) => eprintln!("0x{:0>16x} - 0x{:0>16x}    {}    {}    {}", range.0, range.1, offset, perms, name),
            None => eprintln!("0x{:0>16x} - 0x{:0>16x}    {}    {}", range.0, range.1, offset, perms),
        }
    }
}

fn cmd_process_restart(debugger_opt: &mut Option<debugger::Debugger>) {
    let debugger = present_debugger!(debugger_opt);

    if debugger.is_alive() {
        match debugger.kill() {
            Ok(_) => {},
            Err(err) => pretty_print_err(err, "Could not kill child", ErrAction::Nothing)
        }
    }

    *debugger_opt = Some(match debugger::Debugger::load(debugger.path()) {
        Ok(debugger) => debugger,
        Err(err) => {
            pretty_print_err(err, "Could not start process", ErrAction::Nothing);
            return;
        }
    });
}

fn cmd_eval(debugger: &mut Option<debugger::Debugger>, mut parser: cmd::CommandSegmentParser) {
    if let Some(expr) = parser.expr(debugger) {
        eprintln!("{} = {}", format!("{}", expr).bold(), format!("0x{:x}", expr).bold());
    }
}

fn pretty_print_stop_cause(_debugger: &debugger::Debugger, cause: tracer::StopCause) {
    match cause {
        tracer::StopCause::Breakpoint(_) => todo!(),
        tracer::StopCause::UnknownBreakpoint => {},
        tracer::StopCause::Exit { status } => {
            eprintln!("Process exitted with status {}", format!("{}", status).bold());
        },
        tracer::StopCause::Signal { .. } => todo!(),
        tracer::StopCause::Stopped { .. } => todo!(),
    }
}

fn cmd_continue_next(debugger: &mut Option<debugger::Debugger>) {
    let debugger = alive_debugger!(debugger);

    loop {
        match debugger.next() {
            Ok(cause) => match cause {
                Some(cause) => {
                    pretty_print_stop_cause(&debugger, cause);
                    break;
                },
                None => {
                    eprintln!("Stopped, unknown why - continuing...");
                }
            },
            Err(err) => {
                pretty_print_err(err, "Failed to wait for next stop", ErrAction::Nothing);
                break;
            },
        }
    }
}

fn cmd_continue_step(debugger: &mut Option<debugger::Debugger>) {
    let debugger = alive_debugger!(debugger);

    match debugger.step() {
        Ok(cause) => match cause {
            Some(cause) => {
                pretty_print_stop_cause(&debugger, cause);
            },
            None => {}
        },
        Err(err) => {
            pretty_print_err(err, "Failed to single step", ErrAction::Nothing);
        },
    }
}

fn cmd_continue_finish(debugger: &mut Option<debugger::Debugger>) {
    let debugger = alive_debugger!(debugger);
    
    match debugger.finish_function() {
        Ok(cause) => {
            match cause {
                tracer::StopCause::Breakpoint(_) => {},
                _ => pretty_print_stop_cause(debugger, cause)
            }
        },
        Err(err) => {
            pretty_print_err(err, "Could not finish function", ErrAction::Nothing);
            return;
        }
    }
}

fn cmd_continue_until(debugger: &mut Option<debugger::Debugger>, mut parser: cmd::CommandSegmentParser) {
    if let Some(location) = parser.expr(debugger) {
        let debugger = alive_debugger!(debugger);

        eprintln!("Continuing to {}", format!("0x{:x}", location).bold());
        match debugger.skip_to(location) {
            Ok(cause) => {
                match cause {
                    tracer::StopCause::Breakpoint(_) => {},
                    _ => pretty_print_stop_cause(debugger, cause)
                }
            },
            Err(err) => {
                pretty_print_err(err, format!("Could not set breakpoint at 0x{:x}", location), ErrAction::Nothing);
                return;
            }
        }
    }
}

fn cmd_memory_read(debugger: &mut Option<debugger::Debugger>, mut parser: cmd::CommandSegmentParser) {
    let op_type = match parser.op_type() {
        Some(op_type) => op_type,
        None => return
    };

    let num = match parser.num() {
        Some(num) => num,
        None => return
    };

    let addr = match parser.expr(debugger) {
        Some(addr) => addr,
        None => return
    };

    let debugger = alive_debugger!(debugger);

    let mut data = vec![0; op_type.size() * num];
    match debugger.read(addr, &mut data) {
        Ok(_) => {},
        Err(err) => {
            pretty_print_err(err, "Could not read memory", ErrAction::Nothing);
            return;
        }
    }

    match op_type {
        cmd::OpType::Qword => {
            eprint!("{}    ", format!("0x{:0>16x}", addr).bold());
            for n in 0..num {
                eprint!("0x{:0>16x}", u64::from_ne_bytes(data[n*8..n*8 + 8].try_into().unwrap()));

                if n % 4 == 3 {
                    eprintln!();
                    if n != num - 1 {
                        eprint!("{}    ", format!("0x{:0>16x}", addr + (n as u64 * 8) + 8).bold());
                    }
                } else if n % 4 == 1 {
                    eprint!("  ");
                } else {
                    eprint!(" ");
                }
            }

            if num % 4 != 0 { eprintln!() }
        },
        cmd::OpType::Dword => {
            eprint!("{}    ", format!("0x{:0>16x}", addr).bold());
            for n in 0..num {
                eprint!("0x{:0>8x}", u32::from_ne_bytes(data[n*4..n*4 + 4].try_into().unwrap()));

                if n % 8 == 7 {
                    eprintln!();
                    if n != num - 1 {
                        eprint!("{}    ", format!("0x{:0>16x}", addr + (n as u64 * 4) + 4).bold());
                    }
                } else if n % 2 == 1 {
                    eprint!("  ");
                } else {
                    eprint!(" ");
                }
            }

            if num % 8 != 0 { eprintln!() }
        },
        cmd::OpType::Word => {
            eprint!("{}    ", format!("0x{:0>16x}", addr).bold());
            for n in 0..num {
                eprint!("0x{:0>4x}", u16::from_ne_bytes(data[n*2..n*2 + 2].try_into().unwrap()));

                if n % 8 == 7 {
                    eprintln!();
                    if n != num - 1 {
                        eprint!("{}    ", format!("0x{:0>16x}", addr + (n as u64 * 2) + 2).bold());
                    }
                } else if n % 2 == 1 {
                    eprint!("  ");
                } else {
                    eprint!(" ");
                }
            }

            if num % 8 != 0 { eprintln!() }
        },
        cmd::OpType::Byte => {
            eprint!("{}    ", format!("0x{:0>16x}", addr).bold());
            for n in 0..num {
                eprint!("{:0>2x}", data[n]);

                if n % 32 == 31 {
                    eprintln!();
                    if n != num - 1 {
                        eprint!("{}    ", format!("0x{:0>16x}", addr + n as u64 + 1).bold());
                    }
                } else if n % 4 == 3 {
                    eprint!(" ");
                }
            }

            if num % 32 != 0 { eprintln!() }
        },
    }
}