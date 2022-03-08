import trcpy

from trcpy.listener import nm, sys, sysv_abi

class Colors:
	BLACK = "\u001b[30m"
	RED = "\u001b[31m"
	GREEN = "\u001b[32m"
	YELLOW = "\u001b[33m"
	BLUE = "\u001b[34m"
	MAGENTA = "\u001b[35m"
	CYAN = "\u001b[36m"
	WHITE = "\u001b[37m"
	RESET = "\u001b[0m"
	BOLD = "\u001b[1m"

def bold(text): return Colors.BOLD + text + Colors.RESET
def black(text): return Colors.BLACK + text + Colors.RESET
def red(text): return Colors.RED + text + Colors.RESET
def green(text): return Colors.GREEN + text + Colors.RESET
def yellow(text): return Colors.YELLOW + text + Colors.RESET
def blue(text): return Colors.BLUE + text + Colors.RESET
def magenta(text): return Colors.MAGENTA + text + Colors.RESET
def cyan(text): return Colors.CYAN + text + Colors.RESET
def white(text): return Colors.WHITE + text + Colors.RESET
	
@sysv_abi
def malloc(trc, size):
	print(blue(f"[ Malloc for {size} bytes"), end="")
	addr = trc.fin()
	print(blue(f" => {hex(addr)} ]"))

@sysv_abi
def free(trc, addr):
	print(red(f"[ Free for {hex(addr)} ]"))

@sysv_abi
def read(trc, fd, buf, size):
	print(green(f"[ read({fd}, <buf>, {size}) => "))
	trc.next()
	print(green(f"{trc.rax()} ]"))

@sysv_abi
def write(trc, fd, buf, size):
	string = trc.read(buf, size)
	print(green(f"[ write({fd}, {string}, {size}) => "))
	trc.next()
	print(green(f"{trc.rax()} ]"))

with trcpy.Tracer() as trc:
	trc.load("./test")

	listener = trcpy.Listener(trc)
	listener.wait(nm("main"))

	listener.on(nm("malloc"), malloc)
	listener.on(nm("free"), free)
	listener.on(sys(trcpy.Syscall.READ), read)
	listener.on(sys(trcpy.Syscall.WRITE), write)
	
	listener.run()