##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

        include Msf::Post::Common
        include Msf::Post::Windows::Registry


        def initialize(info={})
                super( update_info( info,
                                'Name' => 'Duqu Registry Check',
                                'Description' => %q{ This module searches for Duqu related registry keys},
                                'License' => MSF_LICENSE,
                                'Author' => [ 'Marcus J. Carey'],
                                'Version' => '$Revision$',
                                'Platform' => [ 'windows' ],
                                'SessionTypes' => [ 'meterpreter' ],
				'References' => [[ 'URL', 'http://r-7.co/w5h7fY' ]]
                        ))
                       
        end

        # Run Method for when run command is issued
        def run
		# query: is a list of registry keys related to duqu. query holds multiple values delimited by comma.
		query = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\"CFID",'
		query += 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\CFID,'
		query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\JmiNET3,'
		query += 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\JmiNET3\FILTER'
                match = 0
                print_status("Searching registry on #{sysinfo['Computer']} for Duqu attributes.")
                keys = query.split(/,/)
		begin 
		        keys.each do |key|
				(key, value) = parse_query(key)
		                has_key = registry_enumkeys(key)
				has_val = registry_enumvals(key)

		                if has_key.include?(value) or has_val.include?(value)
		                        print_good("#{sysinfo['Computer']}: #{key}\\#{value} found in registry.")
		                        match += 1
		        	end
			end
		rescue;	end

                print_status("#{sysinfo['Computer']}: #{match} result(s) found in registry.")
        end

	def parse_query(key)
		path = key.split("\\")
		value = path[-1]
		path.pop
		key = path.join("\\")
		return key, value
	end
	
end