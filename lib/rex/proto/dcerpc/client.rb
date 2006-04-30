module Rex
module Proto
module DCERPC
class Client

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/proto/dcerpc/exceptions'
require 'rex/text'
require 'rex/proto/smb/exceptions'

	attr_accessor :handle, :socket, :options, :last_response, :context, :no_bind, :ispipe, :smb

	# initialize a DCE/RPC Function Call
	def initialize(handle, socket, useroptions = Hash.new)
		self.handle = handle
		self.socket = socket
		self.options = {
			'smb_user'   => '',
			'smb_pass'   => '',
			'smb_pipeio' => 'rw' 
		}
		
		self.options.merge!(useroptions)
		
		# If the caller passed us a smb_client object, use it and
		# and skip the connect/login/ipc$ stages of the setup
		if (self.options['smb_client'])
			self.smb = self.options['smb_client']
		end
	
		# we must have a valid handle, regardless of everything else
		raise ArgumentError, 'handle is not a Rex::Proto::DCERPC::Handle' if !self.handle.is_a?(Rex::Proto::DCERPC::Handle)

		# we do this in case socket needs setup first, ie, socket = nil
		if !self.options['no_socketsetup']
			self.socket_check()
		end
		
		raise ArgumentError, 'socket can not read' if !self.socket.respond_to?(:read)
		raise ArgumentError, 'socket can not write' if !self.socket.respond_to?(:write)

		if !self.options['no_autobind']
			self.bind()
		end
	end

	def socket_check()
		if self.socket == nil
			self.socket_setup()
		end

		case self.handle.protocol
			when 'ncacn_ip_tcp'
				if self.socket.type? != 'tcp'
					raise "ack, #{self.handle.protocol} requires socket type tcp, not #{self.socket.type?}!"
				end
			when 'ncacn_np'
				if self.socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
					self.ispipe = 1
				elsif self.socket.type? == 'tcp'
					self.smb_connect()
				else
					raise "ack, #{self.handle.protocol} requires socket type tcp, not #{self.socket.type?}!"
				end
				# don't support ncacn_ip_udp yet
				## when 'ncacn_ip_udp'
				## if self.socket.type? != 'udp'
				## raise "ack, #{self.handle.protocol} requires socket type tcp, not #{self.socket.type?}!"
				## end
			else
				raise "Unsupported protocol : #{self.handle.protocol}"
		end
	end

	# Create the appropriate socket based on protocol
	def socket_setup()
	 	ctx = { 'Msf' => options['Msf'], 'MsfExploit' => options['MsfExploit'] }
		self.socket = case self.handle.protocol
			when 'ncacn_ip_tcp' then Rex::Socket.create_tcp('PeerHost' => self.handle.address, 'PeerPort' => self.handle.options[0], 'Context' => ctx)
			when 'ncacn_np' then begin 
				socket = ''
				begin
				timeout(10) {
					socket = Rex::Socket.create_tcp('PeerHost' => self.handle.address, 'PeerPort' => 445, 'Context' => ctx)
				}
				rescue Timeout::Error, Rex::ConnectionRefused
					socket = Rex::Socket.create_tcp('PeerHost' => self.handle.address, 'PeerPort' => 139, 'Context' => ctx)
				end
				socket
			end
			else nil
		end

		# Add this socket to the exploit's list of open sockets
		options['MsfExploit'].add_socket(self.socket) if (options['MsfExploit'])
	end

	def smb_connect()
		require 'rex/proto/smb/simpleclient'

		if(not self.smb)
			if self.socket.peerport == 139
				smb = Rex::Proto::SMB::SimpleClient.new(self.socket)
			else
				smb = Rex::Proto::SMB::SimpleClient.new(self.socket, true)
			end

			smb.login('*SMBSERVER', self.options['smb_user'], self.options['smb_pass'])
			smb.connect('IPC$')
			self.smb = smb
			p "CREATED NEW SMB!!!!"
		end
		
		f = self.smb.create_pipe(self.handle.options[0])
		f.mode = self.options['smb_pipeio']
		self.socket = f
	end

	def read()
		raw_response = ''
			
		if self.socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
			begin
				if self.options['segment_read']
					while(true)
						data = self.socket.read((rand(20)+5), rand(1024)+1)
						last if ! data.length
						raw_response += data
					end
				else
					raw_response = self.socket.read()
				end
			rescue Rex::Proto::SMB::Exceptions::NoReply
				# I don't care if I didn't get a reply...
			rescue Rex::Proto::SMB::Exceptions::ErrorCode => exception
				if exception.error_code != 0xC000014B 
					raise exception
				end
			end
		else # must be a regular socket
			if self.socket.type? == 'tcp'
				if self.options['segment_read']
					while (true)
						data = self.socket.get_once(rand(5)+5, 10)
						break if data == nil
						break if ! data.length
						raw_response << data
					end
				else 
					raw_response = self.socket.get_once(-1, 5)
				end
			else
				raw_response = self.socket.read(0xFFFFFFFF / 2 - 1)  # read max data
			end
		end

		raw_response
	end

	def write(data)
	
		if (! self.options['segment_write'] or (self.handle.protocol == 'ncacn_np'))
			self.socket.write(data)
		else
			while (data.length > 0)
				len = self.socket.write( data.slice!(0, (rand(20)+5)) )
			end
		end

		data.length
	end

	def bind()
		require 'rex/proto/dcerpc/packet'
		bind = ''
		context = ''
		if self.options['fake_multi_bind']
			bind, context = Rex::Proto::DCERPC::Packet.make_bind_fake_multi(self.handle.uuid[0], self.handle.uuid[1])
		else
			bind, context = Rex::Proto::DCERPC::Packet.make_bind(self.handle.uuid[0], self.handle.uuid[1])
		end

		raise 'make_bind failed' if !bind

		self.write(bind)
		raw_response = self.read()
		response = Rex::Proto::DCERPC::Response.new(raw_response)
		self.last_response = response
		if response.type == 12 or response.type == 15
			if self.last_response.ack_result[context] == 2
				raise "Could not bind to #{self.handle}"
			end
			self.context = context
		else 
			raise "Could not bind to #{self.handle}"
		end
	end

	# Perform a DCE/RPC Function Call
	def call(function, data)

		frag_size = data.length
		if options['frag_size']
			frag_size = options['frag_size']
		end
		object_id = ''
		if options['object_call']
			object_id = self.handle.uuid[0]
		end
		if options['random_object_id']
			object_id = Rex::Proto::DCERPC::UUID.uuid_unpack(Rex::Text.rand_text(16))
		end

		call_packets = Rex::Proto::DCERPC::Packet.make_request(function, data, frag_size, self.context, object_id)
		call_packets.each { |packet|
			self.write(packet)
		}

		raw_response = self.read()
		if (raw_response == nil or raw_response.length == 0)
			raise Rex::Proto::DCERPC::Exceptions::NoResponse
		end
		self.last_response = Rex::Proto::DCERPC::Response.new(raw_response)

		if self.last_response.type == 3
			e = Rex::Proto::DCERPC::Exceptions::Fault.new
			e.fault = self.last_response.status
			raise e
		end
			
		self.last_response.stub_data
	end

	# Process a DCERPC response packet from a socket
	def self.read_response (socket, timeout=5) 

		data = socket.get_once(-1, timeout)

		# We need at least 10 bytes to find the FragLen
		if (! data or data.length() < 10)
			return
		end
	
		# Pass the first 10 bytes to the constructor
		resp = Rex::Proto::DCERPC::Response.new(data.slice!(0, 10))
		
		# Something went wrong in the parser...
		if (! resp.frag_len)
			return resp
		end

		# Do we need to read more data?
		if (resp.frag_len > (data.length + 10))
			begin
				data << socket.timed_read(resp.frag_len - data.length - 10, timeout)
			rescue Timeout::Error
			end
		end

		# Still missing some data...
		if (data.length() != resp.frag_len - 10)
			$stderr.puts "Truncated DCERPC response :-("
			return resp
		end

		resp.parse(data)
		return resp
	end
	
end
end
end
end
