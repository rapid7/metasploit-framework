module Rex

###
#
# This class provides os-specific functionality
#
###
module Compat

STD_INPUT_HANDLE  = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE  = -12

GENERIC_READ    = 0x80000000
GENERIC_WRITE   = 0x40000000
GENERIC_EXECUTE = 0x20000000

FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING    = 0x00000003 

ENABLE_LINE_INPUT = 2
ENABLE_ECHO_INPUT = 4
ENABLE_PROCESSED_INPUT = 1



#
# Platform detection
#

@@is_windows = @@is_cygwin = @@is_macosx = @@is_linux = @@is_bsdi = @@is_freebsd = @@is_netbsd = @@is_openbsd = @@is_java = false
@@loaded_win32api  = false
@@loaded_dl        = false
@@loaded_tempfile  = false
@@loaded_fileutils = false


def self.is_windows
	return @@is_windows if @@is_windows
	@@is_windows = (RUBY_PLATFORM =~ /mswin32/) ? true : false
end

def self.is_cygwin
	return @@is_cygwin if @@is_cygwin
	@@is_cygwin = (RUBY_PLATFORM =~ /mswin32/) ? true : false
end

def self.is_macosx
	return @@is_macosx if @@is_macosx
	@@is_macosx = (RUBY_PLATFORM =~ /darwin/) ? true : false
end

def self.is_linux
	return @@is_linux if @@is_linux
	@@is_linux = (RUBY_PLATFORM =~ /linux/) ? true : false
end

def self.is_bsdi
	return @@is_bsdi if @@is_bsdi
	@@is_bsdi = (RUBY_PLATFORM =~ /bsdi/i) ? true : false
end

def self.is_netbsd
	return @@is_netbsd if @@is_netbsd
	@@is_netbsd = (RUBY_PLATFORM =~ /netbsd/) ? true : false
end

def self.is_freebsd
	return @@is_freebsd if @@is_freebsd
	@@is_freebsd = (RUBY_PLATFORM =~ /freebsd/) ? true : false
end

def self.is_openbsd
	return @@is_openbsd if @@is_openbsd
	@@is_openbsd = (RUBY_PLATFORM =~ /openbsd/) ? true : false
end

def self.is_java
	return @@is_java if @@is_java
	@@is_java = (RUBY_PLATFORM =~ /java/) ? true : false
end

def self.open_browser(url='http://metasploit.com/')
	case RUBY_PLATFORM
	when /mswin32/
		@s32 ||= DL.dlopen("shell32.dll")
		se = @s32['ShellExecute', 'LPPPPPL']
		se.call(nil, "open".to_s, url, nil, nil, 0)	
	when /darwin/
		system("open #{url}")
	else
		system("firefox #{url} &")
	end
end

def self.open_email(addr)
	case RUBY_PLATFORM
	when /mswin32/
		@s32 ||= DL.dlopen("shell32.dll")
		se = @s32['ShellExecute', 'LPPPPPL']
		se.call(nil, "open".to_s, url, nil, nil, 0)
	when /darwin/
		system("open mailto:#{addr}")
	else
		# ?
	end
end

def self.getenv(var)
	if (is_windows and @@loaded_win32api)
		f = Win32API.new("kernel32", "GetEnvironmentVariable", ["P", "P", "I"], "I")
		buff = "\x00" * 65536
		sz = f.call(var, buff, buff.length)
		return nil if sz == 0
		buff[0,sz]	
	else
		ENV[var]
	end
end

def self.setenv(var,val)
	if (is_windows and @@loaded_win32api)
		f = Win32API.new("kernel32", "SetEnvironmentVariable", ["P", "P"], "I")
		f.call(var, val + "\x00")
	else
		ENV[var]= val
	end
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
# Call WinExec (equiv to system("cmd &"))
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
# Get a handle to Win32 /dev/null
#
def self.win32_dev_null
	begin
		@@k32 ||= DL.dlopen("kernel32.dll")
		crt = @@k32['CreateFile', 'LPLLLLLL']

		hnd, rs = crt.call(
			("NUL\x00").to_ptr, 
			-GENERIC_READ | -GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			0,
			OPEN_EXISTING,
			0,
			0
		)
		
		hnd
	rescue ::Exception
		raise $!	
	end
end

#
# Set a standard handle to a new value
#
def self.win32_set_std_handle(std, hnd)
	begin
	
		sid = STD_OUTPUT_HANDLE
		case std.downcase
		when 'stdin'
			sid = STD_INPUT_HANDLE
		when 'stderr'
			sid = STD_ERROR_HANDLE
		when 'stdout'
			sid = STD_OUTPUT_HANDLE
		else
			raise ArgumentError, "Standard handle must be one of stdin/stdout/stderr"
			return
		end
	
		@@k32 ||= DL.dlopen("kernel32.dll")
		ssh = @@k32['SetStdHandle', 'LLL']
		ssh.call(sid, hnd)
		
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

#
# Copy a file to a temporary path
#

def self.temp_copy(path)
	raise RuntimeError,"missing Tempfile" if not @@loaded_tempfile	
	fd = File.open(path, "rb")
	tp = Tempfile.new("msftemp")	
	tp.write(fd.read(File.size(path)))
	tp.close
	fd.close	
	tp
end

#
# Delete an opened temporary file
#

def self.temp_delete(tp)
	raise RuntimeError,"missing FileUtils" if not @@loaded_fileutils
	begin
		FileUtils.rm(tp.path)
	rescue
	end
end


#
# Initialization
#

if(is_windows)
	begin
		require "Win32API"
		@@loaded_win32api = true
	rescue ::Exception
	end
end


begin
	require "dl"
	@@loaded_dl = true
rescue ::Exception
end

begin
	require "tempfile"
	@@loaded_tempfile = true
rescue ::Exception
end

begin
	require "fileutils"
	@@loaded_fileutils = true
rescue ::Exception
end



end
end
