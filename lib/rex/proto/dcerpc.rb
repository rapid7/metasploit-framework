#!/usr/bin/env ruby -w

##
#    Name: Rex::Proto::DCERPC
# Purpose: Provide DCERPC creation and processing routines
#  Author: H D Moore <hdm [at] metasploit.com>
# Version: $Revision$
##

module Rex
module Proto
class DCERPC

require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/response'
require 'rex/text'

	#
	# Process a DCERPC response packet from a socket
	#
	def read_response (socket) 
		head = socket.timed_read(10, 5)
		if (! head or head.length() != 10)
			return
		end
		
		resp = Rex::Proto::DCERPC::Response.new(head)
		
		if (! resp.frag_len)
			return resp
		end
		
		body = socket.timed_read(resp.frag_len, 10)
		if (! body or body.length() != resp.frag_len) 
			return resp
		end
		
		resp.parse(body)
		return resp
	end


	#
	# Create a standard DCERPC BIND request packet
	#
	def make_bind (uuid, vers)	
		u = Rex::Proto::DCERPC::UUID.new()
		
		# Process the version strings ("1.0", 1.0, "1", 1)
		bind_vers_maj, bind_vers_min = u.vers_to_nums(vers)
		xfer_vers_maj, xfer_vers_min = u.vers_to_nums(u.xfer_syntax_vers)

		# Create the bind request packet
		buff = 
		[
			5,      # major version 5
			0,      # minor version 0
			11,     # bind type
			3,      # flags
			0x10000000,  # data representation
			72,     # frag length
			0,      # auth length
			0,      # call id
			5840,   # max xmit frag
			5840,   # max recv frag
			0,      # assoc group
			1,      # num ctx items
			0,      # context id
			1,      # num trans items
			u.uuid_pack(uuid),   # interface uuid
			bind_vers_maj,       # interface major version
			bind_vers_min,       # interface minor version
			u.xfer_syntax_uuid,  # transfer syntax
			xfer_vers_maj,       # syntax major version
			xfer_vers_min,       # syntax minor version 
		].pack('CCCCNvvVvvVVvvA16vvA16vv')
	end

	#
	# Create an obfuscated DCERPC BIND request packet
	#
	def make_bind_fake_multi(uuid, vers, bind_head=rand(6)+10, bind_tail=rand(3)+1)	
		u = Rex::Proto::DCERPC::UUID.new()
		
		# Process the version strings ("1.0", 1.0, "1", 1)
		bind_vers_maj, bind_vers_min = u.vers_to_nums(vers)
		xfer_vers_maj, xfer_vers_min = u.vers_to_nums(u.xfer_syntax_vers)
		
		bind_total = bind_head + bind_tail + 1
		bind_size  = (bind_total * 40) + 32
		real_ctx, ctx = 0, 0

		# Create the header of the bind request
		data = 
		[
			5,      # major version 5
			0,      # minor version 0
			11,     # bind type
			3,      # flags
			0x10000000,  # data representation
			bind_size,   # frag length
			0,      # auth length
			0,      # call id
			5840,   # max xmit frag
			5840,   # max recv frag
			0,      # assoc group
			1,      # num ctx items
			bind_total,  # context id
		].pack('CCCCNvvVvvVV')
		
		# Generate the fake UUIDs prior to the real one
		1.upto(bind_head) do ||
			# Generate some random UUID and versions
			rand_uuid = Rex::Text.rand_text(16)
			rand_imaj = rand(6)			
			rand_imin = rand(4)
			
			data += 
			[
				ctx += 1,   # context id
				1,          # num trans items		
				rand_uuid,  # interface uuid
				rand_imaj,  # interface major version
				rand_imin,  # interface minor version
				u.xfer_syntax_uuid,  # transfer syntax
				xfer_vers_maj,       # syntax major version
				xfer_vers_min,       # syntax minor version 
			].pack('vvA16vvA16vv')
		end
		
		# Stuff the real UUID onto the end of the buffer
		real_ctx = ctx;
		data += 
		[
			ctx += 1, # context id
			1,        # num trans items		
			u.uuid_pack(uuid),   # interface uuid
			bind_vers_maj,       # interface major version
			bind_vers_min,       # interface minor version
			u.xfer_syntax_uuid,  # transfer syntax
			xfer_vers_maj,       # syntax major version
			xfer_vers_min,       # syntax minor version 
		].pack('vvA16vvA16vv')
		
		# Generate the fake UUIDs after the real one
		1.upto(bind_tail) do ||
			# Generate some random UUID and versions
			rand_uuid = Rex::Text.rand_text(16)
			rand_imaj = rand(6)			
			rand_imin = rand(4)
			
			data += 
			[
				ctx += 1,   # context id
				1,          # num trans items		
				rand_uuid,  # interface uuid
				rand_imaj,  # interface major version
				rand_imin,  # interface minor version
				u.xfer_syntax_uuid,  # transfer syntax
				xfer_vers_maj,       # syntax major version
				xfer_vers_min,       # syntax minor version 
			].pack('vvA16vvA16vv')
		end
		
		# Return both the bind packet and the real context_id
		return data, real_ctx
	end
	
	#
	# Create a standard DCERPC ALTER_CONTEXT request packet
	#
	def make_alter_context (uuid, vers)	
		u = Rex::Proto::DCERPC::UUID.new()
		
		# Process the version strings ("1.0", 1.0, "1", 1)
		bind_vers_maj, bind_vers_min = u.vers_to_nums(vers)
		xfer_vers_maj, xfer_vers_min = u.vers_to_nums(u.xfer_syntax_vers)

		buff = 
		[
			5,      # major version 5
			0,      # minor version 0
			14,     # alter context
			3,      # flags
			0x10000000,     # data representation
			72,     # frag length
			0,      # auth length
			0,      # call id
			5840,   # max xmit frag
			5840,   # max recv frag
			0,      # assoc group
			1,      # num ctx items
			0,      # context id
			1,      # num trans items
			u.uuid_pack(uuid),   # interface uuid
			bind_vers_maj,       # interface major version
			bind_vers_min,       # interface minor version
			u.xfer_syntax_uuid,  # transfer syntax
			xfer_vers_maj,       # syntax major version
			xfer_vers_min,       # syntax minor version 
    	].pack('CCCCNvvVvvVVvvA16vvA16vv')
	end
	

	#
	# Used to create a piece of a DCERPC REQUEST packet
	#
	def make_request_chunk (flags=3, opnum=0, data="", ctx=0)	

		dlen = data.length
		flen = dlen + 24
		
		buff = 
		[
			5,      # major version 5
			0,      # minor version 0
			0,      # request type
			flags,  # flags
			0x10000000,     # data representation
			flen,   # frag length
			0,      # auth length
			0,      # call id
			dlen,   # alloc hint
			ctx,    # context id
			opnum,  # operation number
    	].pack('CCCCNvvVVvv') + data
	end	

	#
	# Used to create standard DCERPC REQUEST packet(s)
	#
	def make_request (opnum=0, data="", size=data.length, ctx=0)	

		dlen = data.length
		chunks, frags = [], []
		ptr = 0
		
		# Break the request into fragments of 'size' bytes
		while ptr < data.length
			chunks.push( data[ ptr, size ] )
			ptr += size
		end
		
		# Process requests with no stub data
		if chunks.length == 0
			frags.push( make_request_chunk(3, opnum, '', ctx) )
			return frags
		end
		
		# Process requests with only one fragment
		if chunks.length == 1
			frags.push( make_request_chunk(3, opnum, chunks[0], ctx) )
			return frags
		end


		# Create the first fragment of the request
		frags.push( make_request_chunk(1, opnum, chunks.shift, ctx) )
		
		# Create all of the middle fragments
		while chunks.length != 1
			frags.push( make_request_chunk(0, opnum, chunks.shift, ctx) )
		end
		
		# Create the last fragment of the request
		frags.push( make_request_chunk(2, opnum, chunks.shift, ctx) )	

		return frags
	end		
	
end
end
end

if $0 == __FILE__
	dcerpc = Rex::Proto::DCERPC.new()
	
	dcerpc.make_bind('367abb81-9844-35f1-ad32-98f038001003', '2.0')
	dcerpc.make_bind_fake_multi('367abb81-9844-35f1-ad32-98f038001003', '2.0')
	dcerpc.make_alter_context('367abb81-9844-35f1-ad32-98f038001003', '2.0')
	
	dcerpc.make_request(1337, '', 1024, 7331)
	dcerpc.make_request(1337, 'ABCD', 1024, 7331)
	dcerpc.make_request(1337, 'ABCD', 3, 7331)
	dcerpc.make_request(1337, 'ABCD', 1, 7331)
	
	puts "[*] All DCERPC tests have passed :-)"	
end
