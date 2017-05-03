##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'net/ntp'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'NTP Enumerator',
			'Description' => 'Obtain time information and ID from NTP server',
			'Author'      => 'RageLtMan',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(123),
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			OptInt.new('CLIENT_TIME', [false, 'Set client current time yyyymmddhhmmss']),
			OptInt.new('NTP_TIMEOUT', [true, 'Query Timeout', 60])
		], self.class)

	end

	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end

	#
	# Runs NTP get query against specified server or using a provided socket
	#
	def run_query(addr, port=123, timeout=nil, udp_sock=nil, c_time=nil)
		resp = Net::NTP.get(
					addr,
					port.to_i || 123,
					timeout, 
					udp_sock,
					c_time
				)
		return if resp.nil? or resp.raw_data.empty?
		resp_fields = resp.send(:packet_data_by_field)

		print_good("#{resp.time} from #{addr} with #{resp_fields[:ident]} ID")

		report_service(
			:host  => addr,
			:proto => 'udp',
			:port  => datastore['RPORT'],
			:name  => 'ntp'
		)

		report_note(
			:host  => addr,
			:proto => 'udp',
			:port  => datastore['RPORT'],
			:type  => 'ntp.ident',
			:data  => "#{resp_fields[:ident]}"
		)
	end

	# Fingerprint rhosts
	def run_batch(batch)
		@ntp_threads = []
		ip_array = []
		# Maybe RangeWalker should pop IPs too
		batch.each {|ip| ip_array << ip}

		begin
			c_time = datastore['CLIENT_TIME']
			udp_sock = nil
			while not ip_array.empty? do
				if @ntp_threads.length < datastore['THREADS'].to_i
					@ntp_threads << Rex::ThreadFactory.spawn("NTPQuery", false) { 
						run_query(ip_array.pop,datastore['RPORT'],datastore['NTP_TIMEOUT'],nil,c_time) 
					}
				else
					Rex::ThreadSafe.sleep(2)
				end
			end

		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Unknown error: #{e.class} #{e}")
		end

	end


end

module Net::NTP #:nodoc:
    ###
    # Sends an NTP datagram to the specified NTP server and returns
    # a hash based upon RFC1305 and RFC2030.
    #
    # Modified to use Rex::Socket, UDP only as the protocol is designed
    # as UDP only. Can still pivot over meterpreter sessions.
    # 
    def self.get(host, port="ntp", timeout=TIMEOUT, sock=nil, client_time_send=Time.new.to_i)
    	# Create a Rex UDP socket, if one is not provided
    	begin
	     	sock ||= Rex::Socket::Udp.create(
	      		'PeerHost' => host,
				'PeerPort' => port == 'ntp' ? 123 : port.to_i,
			)
		rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
			#print_error("Socket error: #{e.class}: #{e}")
			raise e
		end

		puts "Connected to #{host}"

		client_localtime      = client_time_send.to_i
		client_adj_localtime  = client_localtime + NTP_ADJ
		client_frac_localtime = frac2bin(client_adj_localtime)

		ntp_msg = (['00011011']+Array.new(12, 0)+[client_localtime, client_frac_localtime.to_s]).pack("B8 C3 N10 B32")

		sock.write ntp_msg
		#sock.flush

		begin
			data = nil
			Timeout::timeout(timeout) do |t|
				data = sock.recvfrom(960)[0]
			end

			Response.new(data) unless data.nil? or data.empty?
		rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
			#print_error("Socket error: #{e.class}: #{e}")
			raise e
		end

    end

	class Response
		# Allow reading raw response
		def raw_data
			@raw_data
		end
	end
end
