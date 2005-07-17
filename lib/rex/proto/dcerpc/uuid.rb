#!/usr/bin/env ruby -w

##
#    Name: Rex::Proto::DCERPC::UUID
# Purpose: Provide DCERPC UUID methods
#  Author: H D Moore <hdm [at] metasploit.com>
# Version: $Revision$
##

module Rex
module Proto
class DCERPC::UUID

	def initialize
		@known_uuids =
		{
			'MGMT'      => [ 'afa8bd80-7d8a-11c9-bef4-08002b102989', '2.0' ],
			'REMACT'    => [ '4d9f4ab8-7d1c-11cf-861e-0020af6e7c57', '0.0' ],
			'SYSACT'    => [ '000001a0-0000-0000-c000-000000000046', '0.0' ],
			'LSA_DS'    => [ '3919286a-b10c-11d0-9ba8-00c04fd92ef5', '0.0' ],
			'SAMR'      => [ '12345778-1234-abcd-ef00-0123456789ac', '1.0' ],
			'MSMQ'      => [ 'fdb3a030-065f-11d1-bb9b-00a024ea5525', '1.0' ],
			'EVENTLOG'  => [ '82273fdc-e32a-18c3-3f78-827929dc23ea', '0.0' ],
			'SVCCTL'    => [ '367abb81-9844-35f1-ad32-98f038001003', '2.0' ]
		}
	end
	
	def uuid_unpack(uuid_bin)
		sprintf("%.8x-%.4x-%.4x-%.4x-%s",
			uuid_bin[ 0, 4].unpack('V')[0],
			uuid_bin[ 4, 2].unpack('v')[0],
			uuid_bin[ 6, 2].unpack('v')[0],
			uuid_bin[ 8, 2].unpack('n')[0],
			uuid_bin[10, 6].unpack('H*')[0]
		)	
	end

	def uuid_pack (uuid_str)
		parts = uuid_str.split('-')
		[ parts[0].hex, parts[1].hex, parts[2].hex, parts[3].hex ].pack('Vvvn') + [ parts[4] ].pack('H*')
	end
	
	def xfer_syntax_uuid ()
		self.uuid_pack('8a885d04-1ceb-11c9-9fe8-08002b104860')
	end
	
	def xfer_syntax_vers ()
		'2.0'
	end
	
	def uuid_by_name (name) 
		if @known_uuids.key?(name)
			@known_uuids[name][0]
		end
	end
	
	def vers_by_name (name)
		if @known_uuids.key?(name)
			@known_uuids[name][1]
		end
	end
	
	def vers_to_nums (vers) 
		vers_maj = vers.to_i
		vers_min = ((vers.to_f - vers.to_i) * 10).to_i
		return vers_maj, vers_min
	end
	
end
end
end

if $0 == __FILE__

	uuid = Rex::Proto::DCERPC::UUID.new()
	strA = '367abb81-9844-35f1-ad32-98f038001003'
	binA = uuid.uuid_pack(strA)
	strB = uuid.uuid_unpack(binA)
	binB = uuid.uuid_pack(strB)
	
	if strA.eql?( strB ) and binA.eql?( binB )
		puts "[*] UUID test is successful"
	else
		puts "[*] UUID test failed"
		p strA + " == " + strB
		p binA + " == " + binB		
	end
	
	if (! uuid.uuid_by_name('MGMT') or ! uuid.vers_by_name('MGMT'))
		puts "[*] UUID lookup failed"
	end

end
