##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Priv
	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'          => "Windows Gather Enumerate Domain",
			'Description'   => %q{
				This module identifies the primary domain via the registry. The registry value used is:
				HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName.
				},
			'License'       => MSF_LICENSE,
			'Version'       => '$Revision$',
			'Platform'      => ['windows'],
			'SessionTypes'  => ['meterpreter'],
			'Author'        => ['Joshua Abraham <jabra[at]rapid7.com>']
		))
	end

	def reg_getvaldata(key,valname)
		value = nil
		begin
			root_key, base_key = client.sys.registry.splitkey(key)
			open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		end
		return value
	end

	def get_domain()
		subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
		v_name = "DCName"
		domain = reg_getvaldata(subkey, v_name)

		if domain != nil and domain != ""
			return domain.split('.')[1].upcase
		else
			return ""
		end
	end

	def run
		domain = get_domain()
		print_error("domain not found") if domain == ""

		report_note(
			:host   => session,
			:type   => 'windows.domain',
			:data   => { :domain => domain },
			:update => :unique_data
		)
		print_good("FOUND Domain: #{domain}")
	end
end

