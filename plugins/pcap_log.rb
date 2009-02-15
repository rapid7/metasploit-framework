##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'packetfu'

module Msf
class Plugin::PcapLog < Msf::Plugin

	include PacketFu
	
	def no_pcaprub_error
		print_error(" -- PcapRub is not installed -- ") 
		print_error("Make sure you have libpcap-dev and try the following commands")
		print_error("to install it:")
		print_error("\t$ cd external/pcaprub/")
		print_error("\t$ ruby extconf.rb && make && sudo make install")
	end
	def usage
		print_error("No interface given") 
		print ("usage: load #{self.name} iface=<iface> [path=<logpath>] [prefix=<logprefix>] [filter=\"<filter>\"]\n")
	end

	def initialize(framework, opts)
		super
		log_path    = opts['path'] || "/tmp"
		log_prefix  = opts['prefix'] || "msf3-session_"
		iface       = opts['iface'] || nil
		filter      = opts['filter']

		begin 
			require 'pcaprub'
		rescue LoadError
			self.no_pcaprub_error
			# what is the right way to deal with errors without printing backtraces
			# so users don't freak out?
			Thread.exit
		end

		if (iface.nil?) 
			self.usage
			Thread.exit
		end

		t = Time.now
		@fname = File.join(log_path, log_prefix).to_s
		@fname += "%04d-%02d-%02d_%02d-%02d-%02d.pcap" % [t.year, t.month, t.mday, t.hour, t.min, t.sec]
		print_status("Logs in #{@fname}")

		stream = PacketFu::Capture.new(:iface => iface, :timeout => 0, :start => true, :filter => filter)
		PacketFu::Write.a2f(:filename => @fname, :arr => [])
		@capture_file = File.open(@fname, "ab")

		@capture_thread = Thread.new {
			print_status("Starting capture thread on interface #{iface}")
			begin
				while true
					while (this_pkt = stream.next)
						if this_pkt 
							PacketFu::Write.append(:file => @capture_file, :pkt => this_pkt)
						else
							print_status("No packets")
						end
					end
					@capture_file.flush
					Rex::ThreadSafe.sleep(1)
				end
			rescue
				print_error($!.message + $!.backtrace.join("\n"))
			end
			print_status("Stopping capture thread")
		}
		@capture_thread.priority -= 1000
	end

	def cleanup
		@capture_file.close
		@capture_thread.kill if @capture_thread && @capture_thread.alive?
	end

	def name
		"pcap_log"
	end

	def desc
		"Logs all socket operations to pcaps (in /tmp by default)"
	end

end
end

