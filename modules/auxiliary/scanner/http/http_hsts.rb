##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'            => 'HTTP Strict Transport Security (HSTS) Detection',
      'Description'     => %q{
        Display HTTP Strict Transport Security (HSTS) information about each system.
      },
      'Author'          => 'Matt "hostess" Andreko <mandreko[at]accuvant.com>',
      'License'         => MSF_LICENSE,
      'DefaultOptions'  => { 'SSL' => true }
    ))

    register_options([
        Opt::RPORT(443)
      ])
  end

  def run_host(ip)
    begin
      res = send_request_cgi({
        'uri'    => '/',
        'method' => 'GET',
        }, 25)

      if res
        hsts = res.headers['Strict-Transport-Security']

        if hsts
          print_good("#{ip}:#{rport} - Strict-Transport-Security:#{hsts}")
          report_note({
            :data => { :data => hsts },
            :type => "hsts.data",
            :host => ip,
            :port => rport
          })
        else
          print_error("#{ip}:#{rport} No HSTS found.")
        end
      else
        print_error("#{ip}:#{rport} No headers were returned.")
      end

    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
