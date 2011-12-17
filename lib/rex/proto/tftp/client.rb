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
	attr_accessor :thread, :context, :sock, :write_sock
	attr_accessor :local_file, :remote_file

	def initialize(params)
		self.local_host = params["LocalHost"] || "0.0.0.0"
		self.local_port = params["LocalPort"] || (1025 + rand(0xffff-1025))
		self.peer_host = params["PeerHost"] || (raise ArgumentError, "Need a peer host.")
		self.peer_port = params["PeerPort"] || 69
		self.context = params["Context"] || {}
		self.local_file = params["LocalFile"] || (raise ArgumentError, "Need a file to send.")
		self.remote_file = params["RemoteFile"] || ::File.split(self.local_file).last
		self.sock = nil
		@shutting_down = false
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
			req = ["\x00\x03", (idx + 1), data_block].pack("A2nA*")
			if self.sock.sendto(req, host, port) > 0
				sent_data += data_block.size
			end
			res = self.sock.recvfrom(65535, 5)
			if res[0] and res[0] =~ /^\x00\x04/
				# emit a status
				sent_blocks += 1
				yield "Sent #{data_block.size} bytes in block #{sent_blocks}" if block_given?
			else
				yield "Got an unexpected response: `#{res[0].inspect}' ; Aborting." if block_given?
				break # and probably yell about it
			end
		end
		if block_given?
			if(sent_data == expected_size)
				yield "Transfer complete!"
			else
				yield "Transfer complete, but with errors."
			end
		end
	end

	def monitor_socket
		yield "Listening for incoming ACKs" if block_given?
		res = self.sock.recvfrom(65535, 5)
		if res[0] and res[0] =~ /^\x00\x04/
			send_data(res[1], res[2]) {|msg| yield msg}
			stop
		end
	end

	def start_client_port
		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => local_host,
			'LocalPort' => local_port,
			'Context'   => context
		)
		if self.sock and block_given?
			yield "Started TFTP client listener on #{local_host}:#{local_port}"
		end

		self.thread = Rex::ThreadFactory.spawn("TFTPClientMonitor", false) {
			monitor_socket {|msg| yield msg}
		}
	end

	def wrq_packet
		req = "\x00\x02"
		req += self.remote_file
		req += "\x00"
		req += "netascii"
		req += "\x00"
	end

	def send_write_request(&block)
		if block_given?
			start_client_port {|msg| yield msg}
		else
			start_client_port 
		end
		self.write_sock = Rex::Socket::Udp.create(
			'PeerHost'  => peer_host,
			'PeerPort'  => peer_port,
			'LocalHost' => local_host,
			'LocalPort' => local_port,
			'Context'   => context
		)
		self.write_sock.sendto(wrq_packet, peer_host, peer_port)
		self.write_sock.close rescue nil
	end

	def stop
		@shutting_down = true
		self.thread.kill
		self.sock.close rescue nil # might be closed already
	end

	#
	# Send an error packet w/the specified code and string
	#
	def send_error(from, num)
		if (num < 1 or num >= ERRCODES.length)
			# ignore..
			return
		end
		pkt = [OpError, num].pack('nn')
		pkt << ERRCODES[num]
		pkt << "\x00"
		send_packet(from, pkt)
	end

end

end
end
end
