require 'rex/socket'
require 'rex/proto/sunrpc/xdr'

module Rex
module Proto
module SunRPC

# XXX: CPORT!
class Client 
	AUTH_NULL = 0
	AUTH_UNIX = 1
	
	PMAP_PROG = 100000
	PMAP_VERS = 2
	PMAP_GETPORT = 3
	
	CALL = 0
	
	MSG_ACCEPTED = 0
	SUCCESS = 0
	
	attr_reader :rhost, :proto_call, :program, :version
	attr_accessor :pport
	
	def initialize()
		@pport = nil
		
		@auth_type = AUTH_NULL
		@auth_data = ''
		
		@call_sock = nil
	end
	
	def create(rhost, rpcport, program, version, proto_create, proto_call)
		if proto_create !~ /^(tcp|udp)$/ || proto_call !~ /^(tcp|udp)$/
			raise ArgumentError, 'Protocol is not "tcp" or "udp"'
		end

		@rhost, @program, @version, @proto_call = rhost, program, version, proto_call.downcase

		proto_num = 0
		if @proto_create.eql?('tcp')
			proto_num = 6
		elsif @proto_create.eql?('udp')
			proto_num = 17
		end

		buf =
			XDR.encode(CALL, 2, PMAP_PROG, PMAP_VERS, PMAP_GETPORT,
				@auth_type, [@auth_data, 400], AUTH_NULL, '',
				@program, @version, proto_num, 0)
		
		sock = SunRPC.make_rpc(@proto_create, @rhost, rpcport)
		SunRPC.send_rpc(sock, buf)
		ret = SunRPC.recv_rpc(sock)
		SunRPC.close_rpc(sock)

		arr = XDR.decode!(ret, Integer, Integer, Integer, String, Integer,
			Integer)
		if arr[1] != MSG_ACCEPTED || arr[4] != SUCCESS || arr[5] == 0
			raise 'SunRPC.create() failed'
		end

		@pport = arr[5]
	end
	
	def call(procedure, buffer)
		buf =
			XDR.encode(CALL, 2, @program, @version, procedure,
				@auth_type, [@auth_data, 400], AUTH_NULL, '')+
			buffer
		
		if !@call_sock
			@call_sock = SunRPC.make_rpc(@proto_call, @rhost, @pport)
		end
		SunRPC.send_rpc(@call_sock, buf)
		ret = SunRPC.recv_rpc(@call_sock)
		
		arr = XDR.decode!(ret, Integer, Integer, Integer, String, Integer)
		if arr[1] != MSG_ACCEPTED || arr[4] != SUCCESS
			raise 'SunRPC.call() failed'
		end
		
		return ret
	end
	
	def destroy()
		SunRPC.close_rpc(@call_sock) if @call_sock
	end
	
	
	def authnull_create()
		@auth_type = AUTH_NULL
		@auth_data = ''
	end
	
	def authunix_create(host, uid, gid, groupz)
		raise ArgumentError, 'Hostname length is too long' if host.length > 255
		raise ArgumentError, 'Too many groups' if groupz.length > 10
		
		@auth_type = AUTH_UNIX
		@auth_data =
			XDR.encode(0, host, uid, gid, groupz) # XXX: TIME! GROUPZ?!
	end
	
	
# XXX: Dirty, integrate some sort of request system into create/call?
	def SunRPC.portmap_req(host, port, rpc_vers, procedure, buffer)
		buf = XDR.encode(CALL, 2, PMAP_PROG, rpc_vers, procedure,
			AUTH_NULL, '', AUTH_NULL, '') + buffer
		
		sock = SunRPC.make_rpc('tcp', host, port)
		SunRPC.send_rpc(sock, buf)
		ret = SunRPC.recv_rpc(sock)
		SunRPC.close_rpc(sock)
		
		arr = XDR.decode!(ret, Integer, Integer, Integer, String, Integer)
		if arr[1] != MSG_ACCEPTED || arr[4] != SUCCESS || arr[5] == 0
			raise 'SunRPC: portmap_req failed'
		end
		
		return ret
	end
	
# Msf::Config.data_directory
#	def SunRPC.program2name(number)
#		File.foreach('data/rpc_names') { |line|
#			next if line.empty? || line =~ /^\s*#/
#			
#			if line =~ /^(\S+?)\s+(\d+)/ && number == $2.to_i
#				return $1
#			end
#		}
#		
#		return "UNKNOWN-#{number}"
#	end
	
	private
	def SunRPC.make_rpc(proto, host, port)
		Rex::Socket.create_tcp(
			'PeerHost'	=> host,
			'PeerPort'	=> port,
			'Proto'		=> proto)
	end
	
	def SunRPC.send_rpc(sock, buf)
		buf = gen_xid() + buf
		if sock.tcp?
			buf = XDR.encode(0x80000000 | buf.length) + buf
		end
		sock.write(buf)
	end
	
	def SunRPC.recv_rpc(sock)
		buf = sock.get_once(-1, 5)
		buf.slice!(0..3)
		if sock.tcp?
			buf.slice!(0..3)
		end
		return buf
	end
	
	def SunRPC.close_rpc(sock)
		sock.close
	end
	
	def SunRPC.gen_xid()
		return XDR.encode(rand(0xffffffff) + 1)
	end
end

end
end
end
