##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'VMWare Enumerate Active Sessions',
      'Description'    => %Q{
        This module will log into the Web API of VMWare and try to enumerate
        all the login sessions.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ])
      ])
  end


  def run_host(ip)
    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      vim_sessions = vim_get_session_list
      case vim_sessions
      when :noresponse
        print_error "Connection error - Received no reply from #{ip}"
      when :error
        print_error "An error has occurred"
      when :expired
        print_error "The session is no longer authenticated"
      else
        output = ''
        vim_sessions.each do |vsession|
          tmp_line = "Name: #{vsession['fullName']} \n\t"
          is_active = vim_session_is_active(vsession['key'],vsession['userName'])
          if is_active == :error
            tmp_line << "Active: N/A \n\t"
          else
            tmp_line << "Active: #{is_active} \n\t"
          end
          tmp_line << "Username: #{vsession['userName']}\n\t"
          tmp_line << "Session Key: #{vsession['key']}\n\t"
          tmp_line << "Locale: #{vsession['locale']}\n\t"
          tmp_line << "Login Time: #{vsession['loginTime']}\n\t"
          tmp_line << "Last Active Time: #{vsession['lastActiveTime']}\n\n"
          print_good tmp_line
          output << tmp_line
        end
        unless output.empty?
          f = store_loot("host.vmware.sessions", "text/plain", datastore['RHOST'], output, "vmware_sessions.txt", "Login Sessions for VMware")
          vprint_good("Login sessions stored in: #{f}")
        end
      end
    else
      print_error "Login failure on #{ip}"
      return
    end
  end
end
