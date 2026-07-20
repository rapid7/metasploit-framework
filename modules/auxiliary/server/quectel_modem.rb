##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/modem'
require 'msf/base/sessions/modem/quectel'

class MetasploitModule < Msf::Auxiliary
  DEFAULT_MAX_CHUNK_SIZE = 1024 # bytes per QISEND chunk
  DEFAULT_PROMPT_TIMEOUT_MS = 5000 # wait for '>' after QISEND (ms)
  DEFAULT_ACK_TIMEOUT_MS = 8000 # wait for SEND OK/FAIL (ms)
  DEFAULT_OPEN_TIMEOUT_MS = 30000 # wait for +QIOPEN URC (ms)
  DEFAULT_CMD_TIMEOUT_MS = 6000 # wait for AT command OK/ERROR (ms)

  # === v0.06.4 modem health / readiness defaults ===============================
  DEFAULT_STARTUP_OK_TIMEOUT_S = 0 # total seconds to wait for first AT OK (0 = no timeout)
  DEFAULT_STARTUP_OK_INTERVAL_MS = 1000  # delay between AT probes at startup (ms)
  DEFAULT_HEALTHCHECK_INTERVAL_S = 3     # seconds between AT probes at runtime
  DEFAULT_HEALTHCHECK_TIMEOUT_MS = 2000  # per-probe AT timeout (ms)
  DEFAULT_HEALTHCHECK_MAX_FAILS = 3 # consecutive failures before marking NOT READY

  DEFAULT_MODEM_SOCKETS = 12 # SID pool size (0..N-1); Quectel Cell Module supports up to 12

  # === Metasploit module proper ============================================

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Quectel Cellular Modem Pivot (Serial AT)',
        'Description' => %q{
          Opens a serial connection to a Quectel cellular modem and registers it as a 'modem' session capable of network
          pivoting. The Quectel modems have a limited number of sockets available, configurable using MODEM_SOCKETS. Once
          the session is established, it can be routed through using the `route` command.
        },
        'Author' => [
          'Deral Heiland',       # original SOCKS5 proxy module
          'Spencer McIntyre'     # native session refactor
        ],
        'License' => MSF_LICENSE,
        'Notes' => { 'Stability' => [], 'Reliability' => [], 'SideEffects' => [] }
      )
    )

    register_options(
      [
        OptString.new('SERIAL', [ true, 'Serial device for Quectel modem', '/dev/ttyUSB0' ]),
        OptInt.new('BAUD', [ true, 'Serial baud rate', 115200 ]),

        # Advanced performance knobs (tune as needed)
        OptInt.new('MODEM_SOCKETS', [ true, 'Number of Quectel socket IDs (SID pool size)', DEFAULT_MODEM_SOCKETS ]),
        OptInt.new('MAX_CHUNK_SIZE', [ true, 'Bytes per AT+QISEND chunk', DEFAULT_MAX_CHUNK_SIZE ]),
        OptInt.new('PROMPT_TIMEOUT_MS', [ true, "Timeout waiting for QISEND '>' prompt (ms)", DEFAULT_PROMPT_TIMEOUT_MS ]),
        OptInt.new('ACK_TIMEOUT_MS', [ true, 'Timeout waiting for SEND OK/FAIL (ms)', DEFAULT_ACK_TIMEOUT_MS ]),
        OptInt.new('OPEN_TIMEOUT_MS', [ true, 'Timeout waiting for +QIOPEN URC (ms)', DEFAULT_OPEN_TIMEOUT_MS ]),
        OptInt.new('CMD_TIMEOUT_MS', [ true, 'Timeout waiting for AT command OK/ERROR (ms)', DEFAULT_CMD_TIMEOUT_MS ]),

        # modem readiness / health watchdog
        OptInt.new('STARTUP_OK_TIMEOUT_S', [ true, 'Startup: total seconds to wait for first AT OK (0 = no timeout)', DEFAULT_STARTUP_OK_TIMEOUT_S ]),
        OptInt.new('STARTUP_OK_INTERVAL_MS', [ true, 'Startup: delay between AT probes (ms)', DEFAULT_STARTUP_OK_INTERVAL_MS ]),
        OptInt.new('HEALTHCHECK_INTERVAL_S', [ true, 'Runtime: seconds between modem AT health probes', DEFAULT_HEALTHCHECK_INTERVAL_S ]),
        OptInt.new('HEALTHCHECK_TIMEOUT_MS', [ true, 'Runtime: AT health probe timeout (ms)', DEFAULT_HEALTHCHECK_TIMEOUT_MS ]),
        OptInt.new('HEALTHCHECK_MAX_FAILS', [ true, 'Runtime: consecutive AT probe failures before marking modem NOT READY', DEFAULT_HEALTHCHECK_MAX_FAILS ])
      ]
    )

    @modem = nil
    @cfg = {}
    @session_registered = false
  end

  def setup
    super
    unless Msf::Sessions::Modem::Quectel::Driver.supported_platform?
      fail_with(Failure::BadConfig,
                "This module uses Linux-specific termios ioctls and cannot run on #{RUBY_PLATFORM}")
    end

    dev = datastore['SERIAL']
    baud = datastore['BAUD'].to_i

    # Build runtime config from datastore (keep everything in seconds/bytes internally)
    @cfg = {
      modem_sockets: [datastore['MODEM_SOCKETS'].to_i, 1].max,
      max_chunk_size: [datastore['MAX_CHUNK_SIZE'].to_i, 1].max,
      prompt_timeout: [datastore['PROMPT_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      ack_timeout: [datastore['ACK_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      open_timeout: [datastore['OPEN_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      cmd_timeout: [datastore['CMD_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      startup_ok_timeout: [datastore['STARTUP_OK_TIMEOUT_S'].to_i, 0].max,
      startup_ok_interval: [datastore['STARTUP_OK_INTERVAL_MS'].to_i, 0].max / 1000.0,
      healthcheck_interval: [datastore['HEALTHCHECK_INTERVAL_S'].to_i, 0].max,
      healthcheck_timeout: [datastore['HEALTHCHECK_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      healthcheck_max_fails: [datastore['HEALTHCHECK_MAX_FAILS'].to_i, 1].max
    }

    # Open the serial port and start the background reader thread.
    begin
      @modem = Msf::Sessions::Modem::Quectel::Driver.new(dev, baud, framework, @cfg)
    rescue ::Errno::ENOENT
      fail_with(Failure::BadConfig, "Serial device not found: #{dev}")
    rescue ::Errno::EACCES
      fail_with(Failure::BadConfig, "Permission denied opening #{dev} - check that your user is in the 'dialout' group")
    rescue ::Errno::EBUSY
      fail_with(Failure::BadConfig, "#{dev} is busy - another process may have it open")
    rescue ::Errno::EIO, ::Errno::ENXIO
      fail_with(Failure::Unreachable, "I/O error on #{dev} - check the USB cable and modem power")
    rescue ::Errno::ENOTTY
      fail_with(Failure::BadConfig, "#{dev} is not a serial port (ioctl TCGETS failed)")
    rescue ::StandardError => e
      fail_with(Failure::Unknown, "Failed to open serial port on #{dev}: #{e.class} #{e.message}")
    end

    # Poll AT until the modem is responsive.
    print_status('Probing modem with AT until OK...')
    begin
      @modem.startup_wait_for_ok(@cfg[:startup_ok_timeout], @cfg[:startup_ok_interval], @cfg[:healthcheck_timeout])
    rescue ::Rex::TimeoutError => e
      fail_with(Failure::TimeoutExpired, e.message)
    rescue ::StandardError => e
      fail_with(Failure::Unknown, "Modem startup probe failed: #{e.class} #{e.message}")
    end
    print_good('Modem is responding to AT commands.')

    # Best-effort wait for the RDY banner (already past it on a warm start).
    print_status('Waiting briefly for RDY URC (best-effort)...')
    @modem.wait_for_rdy(5)

    # Disable echo so URC parsing is not confused by command echoes.
    begin
      @modem.send_at('ATE0', @cfg[:cmd_timeout])
    rescue ::StandardError => e
      fail_with(Failure::Unknown, "Failed to disable echo (ATE0): #{e.class} #{e.message}")
    end

    # Close any leftover socket connections from a previous session (e.g. MSF
    # crashed without sending AT+QICLOSE). Errors are silently ignored - a SID
    # that is not open will return ERROR, which is expected.
    print_status('Closing any leftover modem socket connections...')
    (0...@cfg[:modem_sockets]).each do |sid|
      @modem.send_at("AT+QICLOSE=#{sid},0", @cfg[:cmd_timeout])
    rescue ::StandardError => e
      nil
    end

    # Start runtime health watchdog now that the modem is known-good.
    @modem.start_health_watchdog
  end

  def cleanup
    # Only close the modem if the session was never registered.
    # Once the session takes ownership, it is responsible for
    # closing the modem via Msf::Sessions::Modem::Quectel#cleanup.
    @modem.close if @modem && !@session_registered
    super
  end

  def run
    unless @modem.modem_ready?
      print_error('Modem is not ready - check serial connection and power')
      return
    end

    sess = Msf::Sessions::Modem::Quectel.new(@modem)
    sess.set_from_exploit(self)
    framework.sessions.register(sess)
    # Transfer modem ownership to the session; cleanup must not close it now.
    @session_registered = true
    print_good("Modem session #{sess.sid} opened (#{@cfg[:modem_sockets]} sockets, #{@cfg[:max_chunk_size]}B chunks)")
    # Return immediately - the session runs independently of this module job.
  end

end
