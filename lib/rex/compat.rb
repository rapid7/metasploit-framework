require 'dl'

module Rex

###
#
# This class provides os-specific functionality
#
###
module Compat

STD_INPUT_HANDLE = -10
ENABLE_LINE_INPUT = 2
ENABLE_ECHO_INPUT = 4
ENABLE_PROCESSED_INPUT = 1


#
# Platform detection
#
def self.is_windows
	(RUBY_PLATFORM =~ /mswin32/) ? true : false
end

def self.is_macosx
	(RUBY_PLATFORM =~ /darwin/) ? true : false
end

def self.is_linux
	(RUBY_PLATFORM =~ /linux/) ? true : false
end


#
# Change the Windows console to non-blocking mode
#
def self.win32_stdin_unblock
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		gsh = @@k32['GetStdHandle', 'LL']
		gcm = @@k32['GetConsoleMode', 'LLP']
		scm = @@k32['SetConsoleMode', 'LLL']
		
		inp = gsh.call(STD_INPUT_HANDLE)[0]
		inf = DL.malloc(DL.sizeof('L'))
		gcm.call(inp, inf)
		old_mode = inf.to_a('L', 1)[0]
		new_mode = old_mode & ~(ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT|ENABLE_PROCESSED_INPUT)
		scm.call(inp, new_mode)
		
	rescue ::Exception
		raise $!
	end
end

#
# Change the Windows console to blocking mode
#
def self.win32_stdin_block
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		gsh = @@k32['GetStdHandle', 'LL']
		gcm = @@k32['GetConsoleMode', 'LLP']
		scm = @@k32['SetConsoleMode', 'LLL']
		
		inp = gsh.call(STD_INPUT_HANDLE)[0]
		inf = DL.malloc(DL.sizeof('L'))
		gcm.call(inp, inf)
		old_mode = inf.to_a('L', 1)[0]
		new_mode = old_mode | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT
		scm.call(inp, new_mode)
		
	rescue ::Exception
		raise $!	
	end
end

#
# Obtain the path to our interpreter
#
def self.win32_ruby_path
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		gmh = @@k32['GetModuleHandle', 'LP']
		gmf = @@k32['GetModuleFileName', 'LLPL']
		
		mod = gmh.call(nil)[0]
		inf = DL.malloc(1024)
		
		gmf.call(mod, inf, 1024)
		return inf.to_s
		
	rescue ::Exception
		raise $!	
	end
end

#
# Call WinExec (equiv to system("cmd &")
#
def self.win32_winexec(cmd)
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		win = @@k32['WinExec', 'LPL']
		win.call(cmd.to_ptr, 0)
	rescue ::Exception
		raise $!	
	end
end

#
# Read directly from the win32 console
#
def self.win32_stdin_read(size=512)
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		gsh = @@k32['GetStdHandle', 'LL']
		rco = @@k32['ReadConsole', 'LLPLPL']

		inp = gsh.call(STD_INPUT_HANDLE)[0]
		buf = DL.malloc(size)
		num = DL.malloc(DL.sizeof('L'))
		rco.call(inp, buf, size, num, 0)
		buf.to_s
		
	rescue ::Exception
		raise $!	
	end
end

#
# Platform independent socket pair
#
def self.pipe

	if (! is_windows())
		# Standard pipes should be fine
		return ::IO.pipe
	end

	# Create a socket connection for Windows
	serv = nil
	port = 1024

	while (! serv and port < 65535)
		begin 
			serv = TCPServer.new('127.0.0.1', (port += 1))
		rescue ::Exception
		end
	end
	
	pipe1 = TCPSocket.new('127.0.0.1', port)

	# Accept the forked child
	pipe2 = serv.accept

	# Shutdown the server
	serv.close
	
	return [pipe1, pipe2]
end


end
end
	
