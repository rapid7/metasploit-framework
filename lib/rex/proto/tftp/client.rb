# $Id$
require 'rex/socket'
require 'rex/proto/tftp'

module Rex
module Proto
module TFTP


#
# TFTP Client class
#
# Note that TFTP has blocks, and so does Ruby. Watch out with the variable names!
class Client

	attr_accessor :local_host, :local_port, :peer_host, :peer_port
	attr_accessor :threads, :context, :server_sock, :client_sock
	attr_accessor :local_file, :remote_file, :mode
	attr_accessor :complete

	# Returns an array of [code, type, msg]
	def parse_tftp_msg(str)
		return nil unless str.length >= 4
		ret = str.unpack("nnA*")
		return ret
	end

	def initialize(params)
		self.threads = []
		self.local_host = params["LocalHost"] || "0.0.0.0"
		self.local_port = params["LocalPort"] || (1025 + rand(0xffff-1025))
		self.peer_host = params["PeerHost"] || (raise ArgumentError, "Need a peer host.")
		self.peer_port = params["PeerPort"] || 69
		self.context = params["Context"] || {}
		self.local_file = params["LocalFile"] || (raise ArgumentError, "Need a file to send.")
		self.remote_file = params["RemoteFile"] || ::File.split(self.local_file).last
		self.mode = params["Mode"] || "octet"
	end

	def blockify_file
		data = ::File.open(self.local_file, "rb") {|f| f.read f.stat.size}
		data.scan(/.{1,512}/)
	end

	def send_data(host,port)
		data_blocks = blockify_file()
		sent_data = 0
		sent_blocks = 0
		expected_blocks = data_blocks.size
		expected_size = data_blocks.join.size
		if block_given? 
			yield "Source file: #{self.local_file}, destination file: #{self.remote_file}"
			yield "Sending #{expected_size} bytes (#{expected_blocks} blocks)"
		end
		data_blocks.each_with_index do |data_block,idx|
			req = [3, (idx + 1), data_block].pack("nnA*")
			if self.server_sock.sendto(req, host, port) > 0
				sent_data += data_block.size
			end
			res = self.server_sock.recvfrom(65535)
			if res
				code, type, msg = parse_tftp_msg(res[0])
				if code == 4
					sent_blocks += 1
					yield "Sent #{data_block.size} bytes in block #{sent_blocks}" if block_given?
				else
					if block_given?
						yield "Got an unexpected response: Code:%d, Type:%d, Message:'%s'. Aborting." % [code, type, msg]
					end
					break 
				end
			end
		end
		if block_given?
			if(sent_data == expected_size)
				yield "Upload complete!"
			else
				yield "Upload complete, but with errors."
			end
		end
	end

	def start_server_socket
		self.server_sock = Rex::Socket::Udp.create(
			'LocalHost' => local_host,
			'LocalPort' => local_port,
			'Context'   => context
		)
		if self.server_sock and block_given?
			yield "Started TFTP client listener on #{local_host}:#{local_port}"
		end

		self.threads << Rex::ThreadFactory.spawn("TFTPServerMonitor", false) {
			monitor_server_sock {|msg| yield msg}
		}

	end

	def monitor_server_sock
			yield "Listening for incoming ACKs" if block_given?
			res = self.server_sock.recvfrom(65535)
			if res[0] and res[0] =~ /^\x00\x04/
				send_data(res[1], res[2]) {|msg| yield msg}
			end
		stop
	end

	def wrq_packet
		req = "\x00\x02"
		req += self.remote_file
		req += "\x00"
		req += self.mode
		req += "\x00"
	end

	def send_write_request(&block)
		if block_given?
			start_server_socket {|msg| yield msg}
		else
			start_server_socket 
		end
		self.client_sock = Rex::Socket::Udp.create(
			'PeerHost'  => peer_host,
			'PeerPort'  => peer_port,
			'LocalHost' => local_host,
			'LocalPort' => local_port,
			'Context'   => context
		)
		self.client_sock.sendto(wrq_packet, peer_host, peer_port)

		self.threads << Rex::ThreadFactory.spawn("TFTPClientMonitor", false) {
			monitor_client_sock {|msg| yield msg}
		}
	end

	def monitor_client_sock
		res = self.client_sock.recvfrom(65535)
		if res[1] # Got a response back, so that's never good; Acks come back on server_sock. 
			code, type, msg = parse_tftp_msg(res[0])
			yield("Aborting, got code:%d, type:%d, message:'%s'" % [code, type, msg]) if block_given?
			stop
		end
	end

	def stop
		self.complete = true
		self.threads.each {|t| t.kill}
		self.server_sock.close rescue nil # might be closed already
		self.client_sock.close rescue nil # might be closed already
	end

end

end
end
end
