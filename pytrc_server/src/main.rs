use std::{io::{BufRead, Write}, os::unix::net::UnixStream};

#[derive(serde::Serialize)]
#[serde(remote = "nix::libc::user_regs_struct")]
struct Regs {
    r15: u64, r14: u64, r13: u64, r12: u64,
    rbp: u64, rbx: u64,
    r11: u64, r10: u64, r9: u64, r8: u64,
    rax: u64, rcx: u64, rdx: u64, rsi: u64, rdi: u64,
    orig_rax: u64,
    rip: u64, cs: u64, eflags: u64, rsp: u64, ss: u64,
    fs_base: u64, gs_base: u64, ds: u64, es: u64, fs: u64, gs: u64,
}

#[derive(serde::Deserialize)]
enum Breakpoint {
    Addr(u64),
    Syscall(i64)
}

#[derive(serde::Deserialize)]
enum Request {
    Ready,
    Load { path: String },
    Pid,
    ContinueUntil { addr: u64 },
    Regs,
    Symbol(String),
    Read { size: u64, addr: u64 },
    ReadStr { addr: u64 },
    Breakpoint(Breakpoint),
    Continue,
    FinishFunction
}


#[derive(serde::Serialize)]
enum StopCause {
    Breakpoint(Option<usize>),
    Exit {
        code: i32
    },
    Signal {
        signal: String,
        dumped: bool
    },
    Stopped {
        signal: String
    }
}

#[derive(serde::Serialize)]
enum Response {
    Error(Error),
    Pid { pid: i32 },
    Ok,
    #[serde(with="Regs")]
    Regs(nix::libc::user_regs_struct),
    Symbol(u64),
    Memory(String),
    Breakpoint(usize),
    Stop(StopCause),
}

#[derive(serde::Serialize)]
enum Error {
    Syntax(String),
    Nix(String),
    Io(String),
    Parse(String),
    NoSymbol(String),
    NoMap(String),
    NotAlive,
    NoContext,
}

fn main() -> std::io::Result<()> {
    let mut debugger = None;

    // FIXME: Don't hard code path
    let mut stream = UnixStream::connect("/tmp/pytrc")?;
    let mut msg = serde_json::to_string(&Response::Ok).unwrap();
    msg.push('\n');
    stream.write_all(msg.as_bytes())?;

    let mut reader = std::io::BufReader::new(stream);

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;

        let request = match serde_json::from_str::<Request>(&line) {
            Ok(req) => req,
            Err(err) => {
                let mut msg = serde_json::to_string(&Response::Error(Error::Syntax(format!("{}", err)))).unwrap();
                msg.push('\n');
                reader.get_mut().write_all(msg.as_bytes())?;
                continue;
            },
        };

        let mut msg = serde_json::to_string(&match handle_request(request, &mut debugger) {
            Ok(response) => response,
            Err(err) => Response::Error(match err {
                trace::debugger::DebuggerError::Nix(err) => Error::Nix(format!("{:?}", err)),
                trace::debugger::DebuggerError::Io(err) => Error::Io(err.to_string()),
                trace::debugger::DebuggerError::Parse(parse) => Error::Parse(format!("{:?}", parse)),
                trace::debugger::DebuggerError::NoSymbol(symbol) => Error::NoSymbol(symbol),
                trace::debugger::DebuggerError::NoMap(name) => Error::NoMap(name),
            }),
        }).unwrap();
        msg.push('\n');
        reader.get_mut().write_all(msg.as_bytes())?;
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
                    return Ok(Response::Error(Error::NotAlive));
                }
            },
            None => {
                return Ok(Response::Error(Error::NoContext));
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
                return Ok(Response::Error(Error::NoContext));
            }
        }
    };
}


fn handle_request(request: Request, debugger: &mut Option<trace::debugger::Debugger>) -> Result<Response, trace::debugger::DebuggerError> {
    match request {
        Request::Ready => {
            Ok(Response::Ok)
        },
        Request::Load { path } => {
            *debugger = Some(trace::debugger::Debugger::load(&path)?);
            Ok(Response::Ok)
        },
        Request::Pid => {
            let debugger = present_debugger!(debugger);
            Ok(Response::Pid { pid: debugger.pid() } )
        },
        Request::ContinueUntil { addr } => {
            let debugger = alive_debugger!(debugger);
            debugger.skip_to(addr)?;
            Ok(Response::Ok)
        },
        Request::Regs => {
            let debugger = alive_debugger!(debugger);
            let regs = debugger.regs()?;
            Ok(Response::Regs(regs))
        },
        Request::Symbol(name) => {
            let debugger = present_debugger!(debugger);
            debugger.refresh_maps()?;
            Ok(Response::Symbol(debugger.sym(&name)?))
        },
        Request::Read { size, addr } => {
            let debugger = alive_debugger!(debugger);
            let mut buf = vec![0u8; size as usize];
            debugger.read(addr, &mut buf)?;

            Ok(Response::Memory(base64::encode(buf)))
        },
        Request::ReadStr { addr } => {
            let debugger = alive_debugger!(debugger);
            let buf = debugger.read_null_terminated(addr)?;

            Ok(Response::Memory(base64::encode(buf)))
        },
        Request::Breakpoint(bp) => {
            let debugger = alive_debugger!(debugger);
            
            match bp {
                Breakpoint::Addr(addr) => Ok(Response::Breakpoint(debugger.break_at(addr)?)),
                Breakpoint::Syscall(num) => Ok(Response::Breakpoint(debugger.break_on_syscall(num)?)),
            }
        },
        Request::Continue => {
            let debugger = alive_debugger!(debugger);

            loop {
                match debugger.next()? {
                    Some(cause) => match cause {
                        trace::tracer::StopCause::Breakpoint(idx) => return Ok(Response::Stop(StopCause::Breakpoint(Some(idx)))),
                        trace::tracer::StopCause::UnknownBreakpoint => return Ok(Response::Stop(StopCause::Breakpoint(None))),
                        trace::tracer::StopCause::Exit { status } => return Ok(Response::Stop(StopCause::Exit { code: status })),
                        trace::tracer::StopCause::Signal { signal, dumped } => return Ok(Response::Stop(StopCause::Signal { signal: signal.to_string(), dumped })),
                        trace::tracer::StopCause::Stopped { signal } => return Ok(Response::Stop(StopCause::Stopped { signal: signal.to_string() })),
                    },
                    None => {
                    },
                }
            }
        },
        Request::FinishFunction => {
            let debugger = alive_debugger!(debugger);
            debugger.finish_function()?;
            Ok(Response::Ok)
        }
    }
}