# -*- coding: binary -*-
module Msf
class Post
module Windows

module NetAPI

	MAX_PREFERRED_LENGTH = -1
	SV_TYPE_ALL = 0xFFFFFFFF
	SV_TYPE_DOMAIN_ENUM = 0x80000000
	SV_TYPE_DOMAIN_BAKCTRL = 10
	SV_TYPE_DOMAIN_CTRL = 4

	def UnicodeByteStringToAscii(str)
		length = (str.index "\0\0\0") + 1
		Rex::Text.to_ascii(str[0..length])
	end

	def netapi_buffer_free(ptr)
		# Free the buffer
		ret = client.railgun.netapi32.NetApiBufferFree(ptr)
		vprint_error("Unable to free buffer, Error Code: #{ret['return']}") unless ret['return'] == 0
	end

	def net_server_enum(server_type=SV_TYPE_ALL, domain=nil)
		result = client.railgun.netapi32.NetServerEnum(
				nil,    # servername
				100,    # level (100/101)
				4,      # bufptr
				MAX_PREFERRED_LENGTH, # prefmaxlen
				4,      # entries read
				4,      # total entries
				server_type, # server_type
				domain,    # domain
				nil     # resume handle
		)

		case result['return']
			when 5
				vprint_error("Access Denied when trying to enum hosts.")
				return nil
			when 6118
				vprint_error("No Browser servers found.")
				return nil
			when 50
				vprint_error("Request not supported.")
				return nil
			when 2184
				vprint_error("Service not installed.")
				return nil
			when 0
				vprint_status("Success.")
			when 87
				vprint_error ("Invalid parameter.")
				return nil
			else
				if result['return'] != 234
					vprint_status("Unaccounted for error code: #{result['return']}")
					return nil
				end
		end

		hosts = read_server_structs(result['bufptr'], result['totalentries'])

		netapi_buffer_free(result['bufptr'])

		return hosts
	end

	def read_server_structs(start_ptr, count)
		base = 0
		struct_size = 8
		hosts = []
		mem = client.railgun.memread(start_ptr, struct_size*count)

		0.upto(count-1) do |i|
			x = {}
			x[:version]= mem[(base + 0),4].unpack("V*")[0]
			nameptr = mem[(base + 4),4].unpack("V*")[0]
			x[:name] = UnicodeByteStringToAscii(client.railgun.memread(nameptr, 255))
			hosts << x
			base += struct_size
		end

		return hosts
	end

	def getSessions(hostname, username)
		result = client.railgun.netapi32.NetSessionEnum(
				hostname,
				nil,
				username,
				10,
				4,
				MAX_PREFERRED_LENGTH,
				4,
				4,
				nil
		)

		case result['return']
			when 5
				vprint_error("#{hostname} Access denied...")
				return nil
			when 53
				vprint_error("Host not found or did not respond: #{hostname}")
				return nil
			when 123
				vprint_error("Invalid host: #{hostname}")
				return nil
			when 0
				vprint_status("#{hostname} Session identified")
			when 2221 #username not found
				return nil
			else
				if result['return'] != 234
					vprint_error("Unaccounted for error code: #{result['return']}")
					return nil
				end
		end

		sessions = read_session_structs(result['bufptr'], result['totalentries'], hostname)

		netapi_buffer_free(result['bufptr'])

		return sessions
	end

	def read_session_structs(start_ptr, count, hostname)
		base = 0
		struct_size = 16
		sessions = []
		mem = client.railgun.memread(start_ptr, struct_size*count)

		0.upto(count-1) do |i|
			sess = {}
			cnameptr = mem[(base + 0),4].unpack("V*")[0]
			usernameptr = mem[(base + 4),4].unpack("V*")[0]
			sess[:usetime] = mem[(base + 8),4].unpack("V*")[0]
			sess[:idletime] = mem[(base + 12),4].unpack("V*")[0]
			sess[:cname] = UnicodeByteStringToAscii(client.railgun.memread(cnameptr,255))
			sess[:username] = UnicodeByteStringToAscii(client.railgun.memread(usernameptr,255))
			sess[:hostname] = hostname
			sessions << sess
			base = base + struct_size
		end

		return sessions
	end

end # NetAPI
end # Windows
end # Post
end # Msf
