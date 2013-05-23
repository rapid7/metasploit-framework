# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/tftp'

module Rex
module Proto
module TFTP

#
# Little util function
#
def self.get_string(data)
	idx = data.index("\x00")
	return nil if not idx
	ret = data.slice!(0, idx)
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
		@shutting_down = false
		@output_dir = nil
		@tftproot = nil

		self.files = []
		self.uploaded = []
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

		self.thread = Rex::ThreadFactory.spawn("TFTPServerMonitor", false) {
			monitor_socket
		}
	end


	#
	# Stop the TFTP server
	#
	def stop
		@shutting_down = true

		# Wait a maximum of 30 seconds for all transfers to finish.
		start = ::Time.now
		while (self.transfers.length > 0)
			::IO.select(nil, nil, nil, 0.5)
			dur = ::Time.now - start
			break if (dur > 30)
		end

		self.files.clear
		self.thread.kill
		self.sock.close rescue nil # might be closed already
	end


	#
	# Register a filename and content for a client to request
	#
	def register_file(fn, content, once = false)
		self.files << {
			:name => fn,
			:data => content,
			:once => once
		}
	end


	#
	# Register an entire directory to serve files from
	#
	def set_tftproot(rootdir)
		@tftproot = rootdir if ::File.directory?(rootdir)
	end


	#
	# Register a directory to write uploaded files to
	#
	def set_output_dir(outdir)
		@output_dir = outdir if ::File.directory?(outdir)
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
		self.sock.sendto(pkt, from[0], from[1])
	end


	#
	# Find the hash entry for a file that may be offered
	#
	def find_file(fname)
		# Files served via register_file() take precedence.
		self.files.each do |f|
			if (fname == f[:name])
				return f
			end
		end

		# Now, if we have a tftproot, see if it can serve from it
		if @tftproot
			return find_file_in_root(fname)
		end

		nil
	end


	#
	# Find the file in the specified tftp root and add a temporary
	# entry to the files hash.
	#
	def find_file_in_root(fname)
		fn = ::File.expand_path(::File.join(@tftproot, fname))

		# Don't allow directory traversal
		return nil if fn.index(@tftproot) != 0

		return nil if not ::File.file?(fn) or not ::File.readable?(fn)

		# Read the file contents, and register it as being served once
		data = data = ::File.open(fn, "rb") { |fd| fd.read(fd.stat.size) }
		register_file(fname, data)

		# Return the last file in the array
		return self.files[-1]
	end


	attr_accessor :listen_host, :listen_port, :context
	attr_accessor :sock, :files, :transfers, :uploaded
	attr_accessor :thread

	attr_accessor :incoming_file_hook

protected

	def find_transfer(type, from, block)
		self.transfers.each do |tr|
			if (tr[:type] == type and tr[:from] == from and tr[:block] == block)
				return tr
			end
		end
		nil
	end

	def save_output(tr)
		self.uploaded << tr[:file]

		return incoming_file_hook.call(tr) if incoming_file_hook

		if @output_dir
			fn = tr[:file][:name].split(File::SEPARATOR)[-1]
			if fn
				fn = ::File.join(@output_dir, Rex::FileUtils.clean_path(fn))
				::File.open(fn, "wb") { |fd|
					fd.write(tr[:file][:data])
				}
			end
		end
	end


	def check_retransmission(tr)
		elapsed = ::Time.now - tr[:last_sent]
		if (elapsed >= tr[:timeout])
			# max retries reached?
			if (tr[:retries] < 3)
				#if (tr[:type] == OpRead)
				#	puts "[-] ack timed out, resending block"
				#else
				#	puts "[-] block timed out, resending ack"
				#end
				tr[:last_sent] = nil
				tr[:retries] += 1
			else
				#puts "[-] maximum tries reached, terminating transfer"
				self.transfers.delete(tr)
			end
		end
	end


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

			r,w,e = ::IO.select(rds,wds,eds,1)

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
				# We handle RRQ and WRQ separately
				#
				if (tr[:type] == OpRead)
					# Are we awaiting an ack?
					if (tr[:last_sent])
						check_retransmission(tr)
					elsif (w != nil and w[0] == self.sock)
						# No ack waiting, send next block..
						chunk = tr[:file][:data].slice(tr[:offset], tr[:blksize])
						if (chunk and chunk.length >= 0)
							pkt = [OpData, tr[:block]].pack('nn')
							pkt << chunk

							send_packet(tr[:from], pkt)
							tr[:last_sent] = ::Time.now

							# If the file is a one-serve, mark it as started
							tr[:file][:started] = true if (tr[:file][:once])
						else
							# No more chunks.. transfer is most likely done.
							# However, we can only delete it once the last chunk has been
							# acked.
						end
					end
				else
					# Are we awaiting data?
					if (tr[:last_sent])
						check_retransmission(tr)
					elsif (w != nil and w[0] == self.sock)
						# Not waiting for data, send an ack..
						#puts "[*] sending ack for block %d" % [tr[:block]]
						pkt = [OpAck, tr[:block]].pack('nn')

						send_packet(tr[:from], pkt)
						tr[:last_sent] = ::Time.now

						# If we had a 0-511 byte chunk, we're done.
						if (tr[:last_size] and tr[:last_size] < tr[:blksize])
							#puts "[*] Transfer complete, saving output"
							save_output(tr)
							self.transfers.delete(tr)
						end
					end
				end
			end
		end
	end


	def next_block(tr)
		tr[:block] += 1
		tr[:last_sent] = nil
		tr[:retries] = 0
	end


	#
	# Dispatch a packet that we received
	#
	def dispatch_request(from, buf)

		op = buf.unpack('n')[0]
		buf.slice!(0,2)

		#XXX: todo - create call backs for status
		#start = "[*] TFTP - %s:%u - %s" % [from[0], from[1], OPCODES[op]]

		case op
		when OpRead
			# Process RRQ packets
			fn = TFTP::get_string(buf)
			mode = TFTP::get_string(buf).downcase

			#puts "%s %s %s" % [start, fn, mode]

			if (not @shutting_down) and (file = self.find_file(fn))
				if (file[:once] and file[:started])
					send_error(from, ErrFileNotFound)
				else
					transfer = {
						:type => OpRead,
						:from => from,
						:file => file,
						:block => 1,
						:blksize => 512,
						:offset => 0,
						:timeout => 3,
						:last_sent => nil,
						:retries => 0
					}

					process_options(from, buf, transfer)

					self.transfers << transfer
				end
			else
				#puts "[-] file not found!"
				send_error(from, ErrFileNotFound)
			end

		when OpWrite
			# Process WRQ packets
			fn = TFTP::get_string(buf)
			mode = TFTP::get_string(buf).downcase

			#puts "%s %s %s" % [start, fn, mode]

			if not @shutting_down
				transfer = {
					:type => OpWrite,
					:from => from,
					:file => { :name => fn, :data => '' },
					:block => 0, # WRQ starts at 0
					:blksize => 512,
					:timeout => 3,
					:last_sent => nil,
					:retries => 0
				}

				process_options(from, buf, transfer)

				self.transfers << transfer
			else
				send_error(from, ErrIllegalOperation)
			end

		when OpAck
			# Process ACK packets
			block = buf.unpack('n')[0]

			#puts "%s %d" % [start, block]

			tr = find_transfer(OpRead, from, block)
			if not tr
				# NOTE: some clients, such as pxelinux, send an ack for block 0.
				# To deal with this, we simply ignore it as we start with block 1.
				return if block == 0

				# If we didn't find it, send an error.
				send_error(from, ErrUnknownTransferId)
			else
				# acked! send the next block
				tr[:offset] += tr[:blksize]
				next_block(tr)

				# If the transfer is finished, delete it
				if (tr[:offset] > tr[:file][:data].length)
					#puts "[*] Transfer complete"
					self.transfers.delete(tr)

					# if the file is a one-serve, delete it from the files array
					if tr[:file][:once]
						#puts "[*] Removed one-serve file: #{tr[:file][:name]}"
						self.files.delete(tr[:file])
					end
				end
			end

		when OpData
			# Process Data packets
			block = buf.unpack('n')[0]
			data = buf.slice(2, buf.length)

			#puts "%s %d %d bytes" % [start, block, data.length]

			tr = find_transfer(OpWrite, from, (block-1))
			if not tr
				# If we didn't find it, send an error.
				send_error(from, ErrUnknownTransferId)
			else
				tr[:file][:data] << data
				tr[:last_size] = data.length
				next_block(tr)

				# Similar to RRQ transfers, we cannot detect that the
				# transfer finished here. We must do so after transmitting
				# the final ACK.
			end

		else
			# Other packets are unsupported
			#puts start
			send_error(from, ErrAccessViolation)

		end
	end

	def process_options(from, buf, tr)
		found = 0
		to_ack = []
		while buf.length >= 4
			opt = TFTP::get_string(buf)
			break if not opt
			val = TFTP::get_string(buf)
			break if not val

			found += 1

			# Is it one we support?
			opt.downcase!

			case opt
			when "blksize"
				val = val.to_i
				if val > 0
					tr[:blksize] = val
					to_ack << [ opt, val.to_s ]
				end

			when "timeout"
				val = val.to_i
				if val >= 1 and val <= 255
					tr[:timeout] = val
					to_ack << [ opt, val.to_s ]
				end

			when "tsize"
				if tr[:type] == OpRead
					len = tr[:file][:data].length
				else
					val = val.to_i
					len = val
				end
				to_ack << [ opt, len.to_s ]

			end
		end

		return if to_ack.length < 1

		# if we have anything to ack, do it
		data = [OpOptAck].pack('n')
		to_ack.each { |el|
			data << el[0] << "\x00" << el[1] << "\x00"
		}

		send_packet(from, data)
	end

end

end
end
end
