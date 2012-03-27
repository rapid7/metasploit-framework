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


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated

	include Msf::Exploit::Remote::DCERPC

	# Scanner mixin should be near last
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'SMB Share Enumeration',
			'Version'     => '$Revision$',
			'Description' => 'Determine what shares are provided by the SMB service',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'DefaultOptions' => {
				'DCERPC::fake_bind_multi' => false
			}
		)

		deregister_options('RPORT', 'RHOST')
	end

	def share_type(val)
		stypes = [
			'DISK',
			'PRINTER',
			'DEVICE',
			'IPC',
			'SPECIAL',
			'TEMPORARY'
		]

		if val > (stypes.length - 1)
			return 'UNKNOWN'
		end

		stypes[val]
	end

	def run_host(ip)

		[[139, false], [445, true]].each do |info|

		datastore['RPORT'] = info[0]
		datastore['SMBDirect'] = info[1]

		begin
			connect
			smb_login

			res = self.simple.client.trans(
				"\\PIPE\\LANMAN",
				(
					[0x00].pack('v') +
					"WrLeh\x00"   +
					"B13BWz\x00"  +
					[0x01, 65406].pack("vv")
				)
			)

			shares = []

			lerror, lconv, lentries, lcount = res['Payload'].to_s[
				res['Payload'].v['ParamOffset'],
				res['Payload'].v['ParamCount']
			].unpack("v4")

			data = res['Payload'].to_s[
				res['Payload'].v['DataOffset'],
				res['Payload'].v['DataCount']
			]

			0.upto(lentries - 1) do |i|
				sname,tmp = data[(i * 20) +  0, 14].split("\x00")
				stype     = data[(i * 20) + 14, 2].unpack('v')[0]
				scoff     = data[(i * 20) + 16, 2].unpack('v')[0]
				if ( lconv != 0)
					scoff -= lconv
				end
				scomm,tmp = data[scoff, data.length - scoff].split("\x00")

				shares << [ sname, share_type(stype), scomm]
			end

			if not shares.empty?
				print_status("#{ip}:#{rport} #{shares.map{|x| "#{x[0]} - #{x[2]} (#{x[1]})" }.join(", ")}")
				report_note(
					:host => ip,
					:proto => 'tcp',
					:port => rport,
					:type => 'smb.shares',
					:data => { :shares => shares },
					:update => :unique_data
				)
			end


			disconnect
			return
		rescue ::Timeout::Error
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError
		rescue ::Rex::Proto::SMB::Exceptions::LoginError
			next
		rescue ::Exception => e
			print_line("Error: #{ip} #{e.class} #{e}")
		end
		end
	end


end
