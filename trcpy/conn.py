import subprocess
import json
import base64
import os, socket

class TracerConnection:
	def __init__(self, path, stdio=None):
		if os.path.exists("/tmp/trcpy"):
			os.remove("/tmp/trcpy")

		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
		self.sock.bind("/tmp/trcpy")
		self.sock.listen(1)

		if stdio is None: stdio = (None, None, None)
		self.proc = subprocess.Popen([path], stdin=stdio[0], stdout=stdio[1], stderr=stdio[2])
		self.conn, _ = self.sock.accept()

		self.recved = b""

		assert self.recv() == "Ok"

	def send(self, cmd):
		self.conn.sendall(json.dumps(cmd).encode() + b"\n")
	
	def recv_line(self):
		while True:
			idx = self.recved.find(b"\n")
			if idx != -1:
				data = self.recved[0:idx]
				self.recved = self.recved[idx + 1:]
				return data
			
			self.recved += self.conn.recv(256)

	def recv(self):
		return json.loads(self.recv_line().decode())

	def cmd(self, cmd):
		self.send(cmd)
		return self.recv()

	def ack(self):
		assert self.cmd("Ready") == "Ok"

	def close(self):
		self.proc.kill()

class TracerException(Exception):
	def __init__(self, message):
		super().__init__(message)
	
	@staticmethod
	def check_err(res):
		if "Error" in res:
			error = res["Error"]

			if "Syntax" in error: raise TracerException("Syntax Error in request: {}".format(error["Syntax"]))
			if "Nix" in error: raise TracerException("Unix Error: {}".format(error["Nix"]))
			if "Io" in error: raise TracerException("Io Error: {}".format(error["Io"]))
			if "Parse" in error: raise TracerException("Parse Error: {}".format(error["Parse"]))
			if "NoSymbol" in error: raise TracerException("Symbol not found: {}".format(error["NoSymbol"]))
			if "NoMap" in error: raise TracerException("Map not found: {}".format(error["NoMap"]))
			if "NotAlive" in error: raise TracerException("Debugger not alive")
			if "NoContext" in error: raise TracerException("No debugging context")

			raise TracerException(str(error))
		
		return res

class StopCause:
	def is_bp(self, bp): return False

class BreakpointStopCause(StopCause):
	def __init__(self, idx):
		self.idx = idx

	def is_bp(self, bp): return self.idx == bp

class ExitStopCause(StopCause):
	def __init__(self, status):
		self.status = status

class Tracer:
	def __init__(self, path="trcpy_server", stdio=None):
		self.conn = TracerConnection(path, stdio)
		self.conn.ack()
	
	def __enter__(self):
		return self
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.close()
	
	def close(self):
		self.conn.close()
	
	def load(self, path):
		TracerException.check_err(self.conn.cmd({ "Load": { "path": path } }))

	def pid(self):
		return TracerException.check_err(self.conn.cmd("Pid"))["Pid"]["pid"]
	
	def continue_until(self, addr):
		TracerException.check_err(self.conn.cmd({ "ContinueUntil": { "addr": addr } }))
	
	def sym(self, name):
		return TracerException.check_err(self.conn.cmd({"Symbol": name}))["Symbol"]
	
	def regs(self):
		return TracerException.check_err(self.conn.cmd("Regs"))["Regs"]
	
	def reg(self, name): return self.regs()[name]
	
	def rip(self): return self.regs()["rip"]
	def eflags(self): return self.regs()["eflags"]
	def orig_rax(self): return self.regs()["orig_rax"]
	
	def rsp(self): return self.regs()["rsp"]
	def rbp(self): return self.regs()["rbp"]

	def rdi(self): return self.regs()["rdi"]
	def rsi(self): return self.regs()["rsi"]

	def rax(self): return self.regs()["rax"]
	def rcx(self): return self.regs()["rcx"]
	def rdx(self): return self.regs()["rdx"]
	def rbx(self): return self.regs()["rbx"]

	def r8(self): return self.regs()["r8"]
	def r9(self): return self.regs()["r9"]
	def r10(self): return self.regs()["r10"]
	def r11(self): return self.regs()["r11"]
	def r12(self): return self.regs()["r12"]
	def r13(self): return self.regs()["r13"]
	def r14(self): return self.regs()["r14"]
	def r15(self): return self.regs()["r15"]

	def break_at(self, addr):
		return TracerException.check_err(self.conn.cmd({"Breakpoint": {"Addr": addr}}))["Breakpoint"]
	
	def break_on_syscall(self, num):
		return TracerException.check_err(self.conn.cmd({"Breakpoint": {"Syscall": num}}))["Breakpoint"]
	
	@staticmethod
	def _stop_cause(cause):
		if "Breakpoint" in cause:
			return BreakpointStopCause(cause["Breakpoint"])
		
		if "Exit" in cause:
			return ExitStopCause(cause["Exit"]["code"])
		
		raise NotImplementedError(f"Unknown stop cause: {cause}")

	def next(self):
		return self._stop_cause(TracerException.check_err(self.conn.cmd("Continue"))["Stop"])
	
	def fin(self):
		TracerException.check_err(self.conn.cmd("FinishFunction"))
		return self.rax()
	
	def read(self, addr, size):
		return base64.b64decode(TracerException.check_err(self.conn.cmd({"Read": { "size": size, "addr": addr }}))["Memory"])
	
	def stdin(self): return self.conn.proc.stdin
	def stdout(self): return self.conn.proc.stdout

	def read_str(self, addr):
		return base64.b64decode(TracerException.check_err(self.conn.cmd({"ReadStr": { "addr": addr }}))["Memory"])