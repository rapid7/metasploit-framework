module Rex
module Proto
module SMB
class SimpleClient

require 'rex/text'
require 'rex/struct2'
require 'rex/proto/smb/constants'
require 'rex/proto/smb/exceptions'
require 'rex/proto/smb/evasions'
require 'rex/proto/smb/crypt'
require 'rex/proto/smb/utils'
require 'rex/proto/smb/client'

# Some short-hand class aliases
CONST = Rex::Proto::SMB::Constants
CRYPT = Rex::Proto::SMB::Crypt
UTILS = Rex::Proto::SMB::Utils
XCEPT = Rex::Proto::SMB::Exceptions
EVADE = Rex::Proto::SMB::Evasions


	class OpenFile
		attr_accessor	:name, :tree_id, :file_id, :mode, :client, :chunk_size
		
		def initialize(client, name, tree_id, file_id)
			self.client = client
			self.name = name
			self.tree_id = tree_id
			self.file_id = file_id
			self.chunk_size = 48000
		end
		
		def delete
			begin
				self.close
			rescue
			end
			self.client.delete(self.name, self.tree_id)
		end
		
		# Close this open file
		def close
			self.client.close(self.file_id, self.tree_id)
		end
		
		# Read data from the file
		def read(length = nil, offset = 0)	
			if (length == nil)
				data = ''
				fptr = offset
				ok = self.client.read(self.file_id, fptr, self.chunk_size)
				while (ok and ok['Payload'].v['DataLenLow'] > 0)
					buff = ok.to_s.slice(
						ok['Payload'].v['DataOffset'] + 4,
						ok['Payload'].v['DataLenLow']
					)
					data << buff
					if ok['Payload'].v['Remaining'] == 0
						break
					end
					fptr += ok['Payload'].v['DataLenLow']
					
					begin
						ok = self.client.read(self.file_id, fptr, self.chunk_size)
					rescue XCEPT::ErrorCode => e
						case e.error_code					
						when 0x00050001
							# Novell fires off an access denied error on EOF
							ok = nil
						else
							raise e
						end
					end
				end

				return data
			else
				ok = self.client.read(self.file_id, offset, length)
				data = ok.to_s.slice(
					ok['Payload'].v['DataOffset'] + 4,
					ok['Payload'].v['DataLenLow']
				)
				return data
			end
		end

		def << (data)
			self.write(data)
		end

		# Write data to the file
		def write(data, offset = 0)	
			# Track our offset into the remote file
			fptr = offset
			
			# Duplicate the data so we can use slice!
			data = data.dup
			
			# Take our first chunk of bytes
			chunk = data.slice!(0, self.chunk_size)
			
			# Keep writing data until we run out
			while (chunk.length > 0)
				ok = self.client.write(self.file_id, fptr, chunk)
				cl = ok['Payload'].v['CountLow']
				
				# Partial write, push the failed data back into the queue
				if (cl != chunk.length)
					data = chunk.slice(cl - 1, chunk.length - cl) + data
				end
				
				# Increment our painter and grab the next chunk
				fptr += cl
				chunk = data.slice!(0, self.chunk_size)
			end
		end
	end
	
	class OpenPipe < OpenFile
		
		# Valid modes are: 'trans' and 'rw'
		attr_accessor :mode
		
		def initialize(*args)
			super(*args)
			self.mode = 'rw'
			@buff = ''
		end
		
		def read_buffer(length, offset=0)
			length ||= @buff.length
			@buff.slice!(0, length)
		end
		
		def read(length = nil, offset = 0)
			case self.mode
			when 'trans'
				read_buffer(length, offset)
			when 'rw'
				super(length, offset)
			else
				raise ArgumentError
			end
		end
		
		def write(data, offset = 0)
			case self.mode
			
			when 'trans'
				write_trans(data, offset)
			when 'rw'
				super(data, offset)
			else
				raise ArgumentError
			end
		end
		
		def write_trans(data, offset=0)
			ack = self.client.trans_named_pipe(self.file_id, data)
			doff = ack['Payload'].v['DataOffset']
			dlen = ack['Payload'].v['DataCount']
			@buff << ack.to_s[4+doff, dlen]
		end
	end
	

# Public accessors
attr_accessor	:last_error

# Private accessors
attr_accessor	:socket, :client, :direct, :shares, :last_share

	# Pass the socket object and a boolean indicating whether the socket is netbios or cifs
	def initialize(socket, direct = false)
		self.socket = socket
		self.direct = direct
		self.client = Rex::Proto::SMB::Client.new(socket)
		self.shares = { }
	end
	
	def login(name = '', user = '', pass = '', domain = '')

		begin
			
			if (self.direct != true)
				self.client.session_request(name)
			end
		
			self.client.negotiate
			ok = self.client.session_setup(user, pass, domain)
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			n = XCEPT::LoginError.new
			n.source = e
			if(e.respond_to?('error_code'))
				n.error_code   = e.error_code
				n.error_reason = e.get_error(e.error_code)
			end
			raise n
		end
		
		return true
	end


	def login_split_start_ntlm1(name = '')

		begin
			
			if (self.direct != true)
				self.client.session_request(name)
			end
			
			# Disable extended security
			self.client.negotiate(false)
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			n = XCEPT::LoginError.new
			n.source = e
			if(e.respond_to?('error_code'))
				n.error_code   = e.error_code
				n.error_reason = e.get_error(e.error_code)
			end
			raise n
		end
		
		return true
	end
	
	
	def login_split_next_ntlm1(user, domain, hash_lm, hash_nt)
		begin
			ok = self.client.session_setup_ntlmv1_prehash(user, domain, hash_lm, hash_nt)
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			n = XCEPT::LoginError.new
			n.source = e
			if(e.respond_to?('error_code'))
				n.error_code   = e.error_code
				n.error_reason = e.get_error(e.error_code)
			end
			raise n
		end
		
		return true			
	end
		
	def connect(share)
		ok = self.client.tree_connect(share)
		tree_id = ok['Payload']['SMB'].v['TreeID']
		self.shares[share] = tree_id
		self.last_share = share
	end
	
	def disconnect(share)
		ok = self.client.tree_disconnect(self.shares[share])
		self.shares.delete(share)
	end	
	
	def open(path, perm)		
		mode   = UTILS.open_mode_to_mode(perm)
		access = UTILS.open_mode_to_access(perm)
		
		ok = self.client.open(path, mode, access)
		file_id = ok['Payload'].v['FileID']
		
		fh = OpenFile.new(self.client, path, self.client.last_tree_id, file_id)
	end
	
	def delete(*args)
		self.client.delete(*args)
	end

	def create_pipe(path, perm = 'c')
		disposition = UTILS.create_mode_to_disposition(perm)
		ok = self.client.create_pipe(path, disposition)
		file_id = ok['Payload'].v['FileID']	
		fh = OpenPipe.new(self.client, path, self.client.last_tree_id, file_id)
	end

	def trans_pipe(fid, data, no_response = nil)
		client.trans_named_pipe(fid, data, no_response)
	end
	
end
end
end
end
