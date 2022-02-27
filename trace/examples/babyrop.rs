use trace::{debugger, tracer::StopCause};


fn main() -> Result<(), debugger::DebuggerError> {
    let mut debugger = debugger::Debugger::load("./babyrop")?;

    debugger.skip_to(debugger.sym("main")?)?;
    debugger.refresh_maps()?;

    eprintln!("Initial stack ptr = 0x{:x}", debugger.regs()?.rsp);

    let malloc = debugger.break_at(debugger.sym("malloc")?)?;
    let free = debugger.break_at(debugger.sym("free")?)?;
    let open = debugger.break_at(debugger.sym("open")?)?;

    let safe_print = debugger.break_at(0x40154c)?;

    loop {
        match debugger.next()? {
            Some(StopCause::Exit { status }) => {
                eprintln!("Exit code {}", status);
                break
            },
            Some(StopCause::Signal { signal, dumped }) => {
                if dumped {
                    let core = debugger.load_core("./core")?;
                    eprintln!("Signal {} (dumped) at 0x{:x}", signal, core.regs().rip);
                } else {
                    eprintln!("Signal {}", signal);
                }
                break
            },
            Some(StopCause::Stopped { signal }) => {
                eprintln!("Stopped for signal {} at 0x{:x}", signal, debugger.regs()?.rip);
                break
            },
            Some(StopCause::UnknownBreakpoint) => {},
            Some(StopCause::Breakpoint(idx)) => {
                if idx == malloc {
                    eprint!("[ Malloc for 0x{:x} bytes ->", debugger.regs()?.rdi);
                    debugger.finish_function()?;
                    let addr = debugger.regs()?.rax;
                    eprintln!(" 0x{:x} (0x{:x} bytes) ]", addr, debugger.read_u64(addr - 8)?);
                } else if idx == free {
                    let addr = debugger.regs()?.rdi;
                    eprint!("[ Free for 0x{:x} (0x{:x} bytes) ->", addr, debugger.read_u64(addr - 8)?);
                    debugger.finish_function()?;
                    eprintln!(" fd=0x{:x} bk=0x{:x} ]", debugger.read_u64(addr)?, debugger.read_u64(addr + 8)?);
                } else if idx == open {
                    let addr = debugger.regs()?.rdi;
                    let flags = debugger.regs()?.rsi;
                    let string = match String::from_utf8(debugger.read_null_terminated(addr)?) {
                        Ok(string) => string,
                        Err(_) => "<invalid>".to_string()
                    };
                    eprint!("[ Open {} ({:b}) ->", string, flags);
                    debugger.finish_function()?;
                    eprintln!(" {} ]", debugger.regs()?.rax);
                } else if idx == safe_print {
                    eprint!("[ Read 0x{:x} bytes to 0x{:x} -> ", debugger.regs()?.rdx, debugger.regs()?.rsi);
                    debugger.step()?;
                    debugger.finish_function()?;
                    if (debugger.regs()?.rax as i64) < 0 {
                        eprintln!("errno = {:x} ]", debugger.read_u64(debugger.sym("errno")?)?);
                    } else {
                        eprintln!("0x{:x} bytes ]", debugger.regs()?.rax);
                    }
                }
            },
            None => {},
        }
    }

    Ok(())
}
