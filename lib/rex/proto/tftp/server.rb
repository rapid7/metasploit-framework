# $Id$
require 'rex/socket'
require 'rex/proto/tftp'

module Rex
module Proto
module TFTP

#
# Little util function
#
def self.get_string(data)
	ret = data.slice!(0,data.index("\x00"))
	# Slice off the nul byte.
	data.slice!(0,1)
	ret
end


##
#
# TFTP Server class
#
##
class Server

	def initialize(port = 69, listen_host = '0.0.0.0', context = {})
		self.listen_host = listen_host
		self.listen_port = port
		self.context = context
		self.sock = nil

		self.files = []
		self.transfers = []
	end


	#
	# Start the TFTP server
	#
	def start
		self.sock = Rex::Socket::Udp.create(
			'LocalHost' => listen_host,
			'LocalPort' => listen_port,
			'Context'   => context
			)

		self.thread = Thread.new {
			monitor_socket
		}
	end


	#
	# Stop the TFTP server
	#
	def stop
		self.transfers.clear
		self.files.clear
		self.thread.kill
		self.sock.close
	end


	#
	# Register a filename and content for a client to request
	#
	def register_file(fn, content)
		self.files << {
			:name => fn,
			:data => content
		}
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


	#
	# Send a single packet to the specified host
	#
	def send_packet(from, pkt)
		# NOTE: I have no idea why self.sock is a normal Socket object, but w/e :)
		self.sock.send(pkt, 0, ::Socket.pack_sockaddr_in(from[1], from[0]))
	end


	#
	# Find the hash entry for a file that may be offered
	#
	def find_file(fname)
		self.files.each do |f|
			if (fname == f[:name])
				return f
			end
		end
		nil
	end


	attr_accessor :listen_host, :listen_port, :context
	attr_accessor :sock, :files, :transfers
	attr_accessor :thread


protected

	#
	# See if there is anything to do.. If so, dispatch it.
	#
	def monitor_socket
		while true
			rds = [@sock]
			wds = []
			self.transfers.each do |tr|
				if (not tr[:last_sent])
					wds << @sock
					break
				end
			end
			eds = [@sock]

			r,w,e = select(rds,wds,eds,1)

			if (r != nil and r[0] == self.sock)
				buf,host,port = self.sock.recvfrom(65535)
				# Lame compatabilitiy :-/
				from = [host, port]
				dispatch_request(from, buf)
			end

			#
			# Check to see if transfers need maintenance
			#
			self.transfers.each do |tr|
				# Are we awaiting an ack?
				if (tr[:last_sent])
					elapsed = Time.now - tr[:last_sent]
					if (elapsed >= 3)
						# max retries reached?
						if (tr[:retries] < 3)
							#puts "[-] ack timed out, resending block"
							tr[:last_sent] = nil
							tr[:retries] += 1
						else
							#puts "[-] maximum tries reached, terminating transfer"
							self.transfers.delete(tr)
						end
					end
				elsif (w != nil and w[0] == self.sock)
					# No ack waiting, send next block..
					chunk = tr[:file][:data].slice(tr[:offset], 512)
					if (chunk and chunk.length >= 0)
						pkt = [OpData, tr[:block]].pack('nn')
						pkt << chunk
						send_packet(tr[:from], pkt)
						tr[:last_sent] = Time.now
					else
						# no more chunks.. transfer is most likely done.
						self.transfers.delete(tr)
					end
				end
			end
		end
	end


	#
	# Dispatch a packet that we received
	#
	def dispatch_request(from, buf)

		op = buf.unpack('n')[0]
		buf.slice!(0,2)

		#start = "[*] TFTP - %s:%u - %s" % [from[0], from[1], OPCODES[op]]

		case op
		when OpRead
			# Process RRQ packets
			fn = TFTP::get_string(buf)
			mode = TFTP::get_string(buf).downcase

			#puts "%s %s %s" % [start, fn, mode]

			if (file = self.find_file(fn))
				self.transfers << {
					:from => from,
					:file => file,
					:block => 1,
					:offset => 0,
					:last_sent => nil,
					:retries => 0
				}
			else
				#puts "[-] file not found!"
				send_error(from, ErrFileNotFound)
			end

		when OpAck
			# Process ACK packets
			block = buf.unpack('n')[0]
			#puts "%s %d" % [start, block]

			self.transfers.each do |tr|
				if (from == tr[:from] and block == tr[:block])
					# acked! send the next block
					tr[:block] += 1
					tr[:offset] += 512
					tr[:last_sent] = nil
					tr[:retries] = 0
				end
			end

		else
			# Other packets are unsupported
			#puts start
			send_error(from, ErrAccessViolation)

		end
	end

end

end
end
end
