from pytrc.conn import BreakpointStopCause, ExitStopCause, Tracer

class Breakpoint:
	def enact(self, tracer): pass

class UnresolvedNamedBreakpoint(Breakpoint):
	def __init__(self, name, offset):
		self.name = name
		self.offset = offset
	
	def addr(self, tracer):
		return tracer.sym(self.name) + self.offset

	def enact(self, tracer):
		return tracer.break_at(self.addr(tracer))

	def __add__(self, rhs):
		self.offset += rhs
		return self

class SyscallBreakpoint(Breakpoint):
	def __init__(self, idx):
		self.idx = idx
	
	def enact(self, tracer):
		return tracer.break_on_syscall(self.idx)

def nm(name): return UnresolvedNamedBreakpoint(name, 0)
def sys(idx): return SyscallBreakpoint(idx)

def sysv_abi(func):
	import inspect

	sig = len(inspect.signature(func).parameters) - 1
	
	SYSV_ABI = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
	def alternate(trc):
		args = []
		regs = trc.regs()
		for i in range(sig):
			args.append(regs[SYSV_ABI[i]])
		
		return func(trc, *args)

	return alternate

class Listener:
	def __init__(self, tracer):
		self.tracer = tracer
		self.breakpoints = {}
	
	def wait(self, bp):
		if isinstance(bp, UnresolvedNamedBreakpoint):
			self.tracer.continue_until(bp.addr(self.tracer))
		else:
			assert False

	def on(self, bp, func):
		if isinstance(bp, Breakpoint): bp = bp.enact(self.tracer)
		self.breakpoints[bp] = func
	
	def run(self):
		while True:
			ev = self.tracer.next()
			
			if isinstance(ev, BreakpointStopCause):
				if ev.idx in self.breakpoints:
					self.breakpoints[ev.idx](self.tracer)
			elif isinstance(ev, ExitStopCause):
				return ev