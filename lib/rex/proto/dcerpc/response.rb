require 'rex/proto/dcerpc/uuid'

module Rex
module Proto
module DCERPC
class Response

	attr_accessor :frag_len, :auth_len, :type, :vers_major, :vers_minor
	attr_accessor :flags, :data_rep, :call_id, :max_frag_xmit, :max_frag_recv
	attr_accessor :assoc_group, :sec_addr_len, :sec_addr, :num_results
	attr_accessor :nack_reason, :xfer_syntax_uuid, :xfer_syntax_vers
	attr_accessor :ack_reason, :ack_result, :ack_xfer_syntax_uuid, :ack_xfer_syntax_vers 	
	attr_accessor :alloc_hint, :context_id, :cancel_cnt, :status, :stub_data
	
	# Create a new DCERPC::Response object, using the first 10 bytes of the packet 
	def initialize (head)
		self.frag_len = head[8,2].unpack('v')[0]
		self.raw = head
		self.ack_result = []
		self.ack_reason = []
		self.ack_xfer_syntax_uuid = []
		self.ack_xfer_syntax_vers = []		
	end
	
	# Parse the contents of a DCERPC response packet and fill out all the fields
	def parse (body)
		self.raw = self.raw + body
		self.type = self.raw[2,1].unpack('C')[0]
		
		uuid = Rex::Proto::DCERPC::UUID
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

			# Keep an offset into the packet handy
			x = 0
			
			# XXX This is still somewhat broken (4 digit ports)
			self.sec_addr = data[26, self.sec_addr_len]
			
			# Move the pointer into the packet forward
			x += 26 + self.sec_addr_len + 2
			
			# Figure out how many results we have (multiple-context binds)
			self.num_results = data[ x, 4 ].unpack('V')[0]
		
			# Move the pointer to the ack_result[0] offset
			x += 4

			# Initialize the ack_result index
			ack = 0
			
			# Scan through all results and add them to the result arrays
			while ack < self.num_results
				self.ack_result[ack] = data[ x + 0, 2 ].unpack('v')[0]
				self.ack_reason[ack] = data[ x + 2, 2 ].unpack('v')[0]
				self.ack_xfer_syntax_uuid[ack] = uuid.uuid_unpack(data[ x + 4, 16 ])
				self.ack_xfer_syntax_vers[ack] = data[ x + 20, 4 ].unpack('V')[0]
				x += 24
				ack += 1
			end
			
			# End of BIND_ACK || ALTER_CONTEXT_RESP
		end

		# BIND_NACK == 13
		if (self.type == 13)
			
			# Decode most of the DCERPC header
			self.vers_major,
			self.vers_minor,
			trash,
			self.flags,
			self.data_rep,
			self.frag_len,
			self.auth_len,
			self.call_id,
			self.nack_reason = data.unpack('CCCCNvvVv')
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
end
