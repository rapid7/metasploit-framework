##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::WmapScanFile
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'HTTP Verb Authentication Bypass Scanner',
      'Description'   => %q{
        This module test for authentication bypass using different HTTP verbs.
      },
      'Author'        => ['et [at] metasploit.com'],
      'License'       => BSD_LICENSE))

    register_options(
      [
        OptString.new('TARGETURI', [true,  "The path to test", '/'])
      ])
  end

  def run_host(ip)
    begin
      test_verbs(ip)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

  def test_verbs(ip)
    verbs = [ 'HEAD', 'TRACE', 'TRACK', 'Wmap', 'get', 'trace' ]

    res = send_request_raw({
      'uri'          => normalize_uri(target_uri.path),
      'method'       => 'GET'
    }, 10)

    return if not res

    if not res.headers['WWW-Authenticate']
      print_status("#{full_uri} - Authentication not required [#{res.code}]")
      return
    end

    auth_code = res.code

    print_status("#{full_uri} - Authentication required: #{res.headers['WWW-Authenticate']} [#{auth_code}]")

    report_note(
      :host   => ip,
      :proto  => 'tcp',
      :sname  => (ssl ? 'https' : 'http'),
      :port   => rport,
      :type   => 'WWW_AUTHENTICATE',
      :data   => "#{target_uri.path} Realm: #{res.headers['WWW-Authenticate']}",
      :update => :unique_data
    )

    verbs.each do |tv|
      resauth = send_request_raw({
        'uri'          => normalize_uri(target_uri.path),
        'method'       => tv
      }, 10)

      next if not resauth

      print_status("#{full_uri} - Testing verb #{tv} [#{resauth.code}]")

      if resauth.code != auth_code and resauth.code <= 302
        print_good("#{full_uri} - Possible authentication bypass with verb #{tv} [#{resauth.code}]")

        # Unable to use report_web_vuln as method is not in list of allowed methods.

        report_note(
          :host   => ip,
          :proto  => 'tcp',
          :sname  => (ssl ? 'https' : 'http'),
          :port   => rport,
          :type   => 'AUTH_BYPASS_VERB',
          :data   => "#{target_uri.path} Verb: #{tv}",
          :update => :unique_data
        )
      end
    end
  end
end
