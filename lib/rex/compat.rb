# -*- coding: binary -*-
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
@@loaded_tempfile  = false
@@loaded_fileutils = false


def self.is_windows
	return @@is_windows if @@is_windows
	@@is_windows = (RUBY_PLATFORM =~ /mswin(32|64)|mingw(32|64)/) ? true : false
end

def self.is_cygwin
	return @@is_cygwin if @@is_cygwin
	@@is_cygwin = (RUBY_PLATFORM =~ /cygwin/) ? true : false
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

def self.is_wow64
	return false if not is_windows
	is64 = false
	begin
		buff = "\x00" * 4
		Win32API.new("kernel32","IsWow64Process",['L','P'],'L').call(-1, buff)
		is64 = (buff.unpack("V")[0]) == 1 ? true : false
	rescue ::Exception
	end
	is64
end

def self.cygwin_to_win32(path)
	if(path !~ /^\/cygdrive/)
		return ::IO.popen("cygpath -w #{path}", "rb").read.strip
	end
	dir = path.split("/")
	dir.shift
	dir.shift
	dir[0] = dir[0] + ":"
	dir.join("\\")
end

def self.open_file(url='')
	case RUBY_PLATFORM
	when /cygwin/
		path = self.cygwin_to_win32(url)
		system(["cmd", "cmd"], "/c", "explorer", path)
	else
		self.open_browser(url)
	end
end

def self.open_browser(url='http://metasploit.com/')
	case RUBY_PLATFORM
	when /cygwin/
		if(url[0,1] == "/")
			self.open_file(url)
		end
		return if not @@loaded_win32api
		Win32API.new("shell32.dll", "ShellExecute", ["PPPPPL"], "L").call(nil, "open", url, nil, nil, 0)
	when /mswin32|mingw/
		return if not @@loaded_win32api
		Win32API.new("shell32.dll", "ShellExecute", ["PPPPPL"], "L").call(nil, "open", url, nil, nil, 0)
	when /darwin/
		system("open #{url}")
	else
		# Search through the PATH variable (if it exists) and chose a browser
		# We are making an assumption about the nature of "PATH" so tread lightly
		if defined? ENV['PATH']
			# "xdg-open" is more general than "sensible-browser" and can be useful for lots of
			# file types -- text files, pcaps, or URLs. It's nearly always
			# going to use the application the user is expecting. If we're not
			# on something Debian-based, fall back to likely browsers.
			['xdg-open', 'sensible-browser', 'firefox', 'firefox-bin', 'opera', 'konqueror', 'chromium-browser'].each do |browser|
				ENV['PATH'].split(':').each do |path|
					# Does the browser exists?
					if File.exists?("#{path}/#{browser}")
						system("#{browser} #{url} &")
						return
					end
				end
			end
		end
	end
end

def self.open_email(addr)
	case RUBY_PLATFORM
	when /mswin32|cygwin/
		return if not @@loaded_win32api
		Win32API.new("shell32.dll", "ShellExecute", ["PPPPPL"], "L").call(nil, "open", "mailto:"+addr, nil, nil, 0)
	when /darwin/
		system("open mailto:#{addr}")
	else
		# ?
	end
end

def self.play_sound(path)
	case RUBY_PLATFORM
	when /cygwin/
		path = self.cygwin_to_win32(path)
		return if not @@loaded_win32api
		Win32API.new("winmm.dll", "sndPlaySoundA", ["SI"], "I").call(path, 0x20000)
	when /mswin32/
		return if not @@loaded_win32api
		Win32API.new("winmm.dll", "sndPlaySoundA", ["SI"], "I").call(path, 0x20000)
	when /darwin/
		system("afplay #{path} >/dev/null 2>&1")
	else
		system("aplay #{path} >/dev/null 2>&1")
	end
end

def self.getenv(var)
	if (is_windows and @@loaded_win32api)
		f = Win32API.new("kernel32", "GetEnvironmentVariable", ["P", "P", "I"], "I")
		buff = "\x00" * 16384
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
# Obtain the path to our interpreter
#
def self.win32_ruby_path
	return nil if ! (is_windows and @@loaded_win32api)
	gmh = Win32API.new("kernel32", "GetModuleHandle", ["P"], "L")
	gmf = Win32API.new("kernel32", "GetModuleFileName", ["LPL"], "L")
	mod = gmh.call(nil)
	inf = "\x00" * 1024
	gmf.call(mod, inf, 1024)
	inf.unpack("Z*")[0]
end

#
# Call WinExec (equiv to system("cmd &"))
#
def self.win32_winexec(cmd)
	return nil if ! (is_windows and @@loaded_win32api)
	exe = Win32API.new("kernel32", "WinExec", ["PL"], "L")
	exe.call(cmd, 0)
end

#
# Verify the Console2 environment
#
def self.win32_console2_verify
	return nil if ! (is_windows and @@loaded_win32api)
	buf = "\x00" * 512
	out = Win32API.new("kernel32", "GetStdHandle", ["L"], "L").call(STD_OUTPUT_HANDLE)
	res = Win32API.new("kernel32","GetConsoleTitle", ["PL"], "L").call(buf, buf.length-1) rescue 0
	( res > 0 and buf.index("Console2 command").nil? ) ? false : true
end

#
# Expand a 8.3 path to a full path
#
def self.win32_expand_path(path)
	return nil if ! (is_windows and @@loaded_win32api)
	glp = Win32API.new('kernel32', 'GetLongPathName', 'PPL', 'L')
	buf = "\x00" * 260
	len = glp.call(path, buf, buf.length)
	buf[0, len]
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
	tp.binmode
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

if(is_windows or is_cygwin)
	begin
		require "Win32API"
		@@loaded_win32api = true
	rescue ::Exception
	end
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

