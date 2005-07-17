#!/usr/bin/env ruby -w

##
#    Name: Rex::Proto::DCERPC::Response
# Purpose: Provide DCERPC Response Packet Objects
#  Author: H D Moore <hdm [at] metasploit.com>
# Version: $Revision$
##

require 'rex/proto/dcerpc/uuid'

module Rex
module Proto
class DCERPC::Response

	attr_accessor :frag_len, :auth_len, :type, :vers_major, :vers_minor
	attr_accessor :flags, :data_rep, :call_id, :max_frag_xmit, :max_frag_recv
	attr_accessor :assoc_group, :sec_addr_len, :sec_addr, :num_results, :ack_result
	attr_accessor :ack_reason, :xfer_syntax_uuid, :xfer_syntax_vers
	
	attr_accessor :alloc_hint, :context_id, :cancel_cnt, :status, :stub_data
	
	def initialize (head)
		self.frag_len = head[8,2].unpack('v')
		self.raw = head
	end
	
	def parse (body)
		self.raw = self.raw + body
		self.type = self.raw[2,1].unpack('C')
		
		uuid = Rex::Proto::DCERPC::UUID.new()
		data = self.raw
		
		# BIND_ACK == 12, ALTER_CONTEXT_RESP == 15
		if (self.type == 12 or self.type == 15)
			
			# Decode most of the DCERPC header
			self.vers_major,
			self.vers_minor,
			trash,
			self.flags,
			self.data_rep,
			self.frag_len,
			self.auth_len,
			self.call_id,
			self.max_frag_xmit,
			self.max_frag_recv,
			self.assoc_group,
			self.sec_addr_len = data.unpack('CCCCNvvVvvVv')

			# XXX This is still somewhat broken (4 digit ports)
			self.sec_addr = data[26, self.sec_addr_len]
			
			# Move the pointer into the packet forward
			data = data[26 + self.sec_addr_len, 0xffff]
			
			self.num_results = data[2,1].unpack('C')
			self.ack_result = data[6,2].unpack('v')
			
			if (self.ack_result != 0)
				self.ack_reason = data[8,2].unpack('v')
				data = data[2, 0xffff]
			end
			
			# Move it even further
			data = data[10, 0xffff]
			
			self.xfer_syntax_uuid = uuid.uuid_unpack(data[0,16])
			self.xfer_syntax_vers = data[16,4].unpack('V')

			# End of BIND_ACK || ALTER_CONTEXT_RESP
		end
		
	
		# RESPONSE == 2
		if (self.type == 2)
		
			# Decode the DCERPC response header
			self.vers_major,
			self.vers_minor,
			trash,
			self.flags,
			self.data_rep,
			self.frag_len,
			self.auth_len,
			self.call_id,
			self.alloc_hint,
			self.context_id,
			self.cancel_cnt = data.unpack('CCCCNvvVVvC')
			
			# Put the application data into self.stub_data
			self.stub_data = data[data.length - self.alloc_hint, 0xffff]
			
			# End of RESPONSE
		end		

		# FAULT == 2
		if (self.type == 3)
		
			# Decode the DCERPC response header
			self.vers_major,
			self.vers_minor,
			trash,
			self.flags,
			self.data_rep,
			self.frag_len,
			self.auth_len,
			self.call_id,
			self.alloc_hint,
			self.context_id,
			self.cancel_cnt,
			trash,
			self.status = data.unpack('CCCCNvvVVvCCV')
			
			# Put the application data into self.stub_data
			self.stub_data = data[data.length - self.alloc_hint, 0xffff]
			
			# End of FAULT
		end	
		
	end
	
protected
	attr_accessor :raw

end
end
end
