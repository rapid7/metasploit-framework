# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Metasploit Payload Handler Detection (TCP/UDP/HTTP/HTTPS)',
      'Description' => %q{
        Detect Metasploit exploit/multi/handler listeners and other reverse
        payload handlers by fingerprinting their wire behavior. Several
        techniques are combined:

          * Staged reverse handlers "talk first": on connect they transmit the
            stage with a 4-byte length prefix whose endianness identifies the
            family
            - little-endian (pack 'V') for Windows native (metsrv)
            - big-endian (pack 'N') for Python/PHP/Java/Android
            - Linux/OSX native stagers send the raw machine-code stage with
              no length prefix, and unix staged shells send a tiny execve("/bin/sh")
              shellcode.
          * Reverse command shells "talk first" with an "echo <token>" probe.
            Echoing the token back marks the shell valid and can capture an
            operator's AutoRunScript / follow-up commands.
          * reverse_http(s) Meterpreter handlers answer any unknown URI with the
            default "It works!" body and Server: Apache. HTTP servers
            (web_delivery, fetch handlers, exploit module servers) return a
            distinctive 404 page.
          * reverse_tcp_ssl handlers stage over TLS; an SSL probe reads the
            stage/echo through the handshake.
          * reverse_udp handlers send the stage in response to any datagram, so
            an optional UDP probe (SCAN_UDP) catches them too.

        Transports that are not TCP/UDP (reverse_sctp, reverse_named_pipe/SMB)
        and silent stageless payloads that wait for the client cannot be
        fingerprinted and appear as a silent open port.
      },
      'Author' => [ 'h00die' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [ CRASH_SAFE ],
        'SideEffects' => [ IOC_IN_LOGS ], # msf console will report sending stage or meterp connection, but then report its invalid
        'Reliability' => []
      }
    )

    register_options(
      [
        OptString.new('PORTS', [ true, 'Ports to scan (e.g. 4444-4460,5555)', '4444-4464' ]),
        OptFloat.new('TIMEOUT', [ true, 'The socket connect timeout in seconds', 1 ]),
        OptFloat.new('FIRST_BYTE_WAIT', [ true, 'How long to wait (seconds) for the handler to send the first stage/probe bytes (shell handlers emit their "echo" probe a little later, so allow some slack)', 5 ]),
        OptFloat.new('IDLE_TIMEOUT', [ true, 'How long to wait (seconds) for more stage data before giving up', 0.75 ]),
        OptInt.new('MAX_STAGE_SIZE', [ true, 'Maximum number of stage bytes to read while fingerprinting', 2 * 1024 * 1024 ]),
        # different types
        OptBool.new('HTTP_PROBE', [ true, 'If a port waits for the client, send an HTTP request to fingerprint MSF HTTP handlers (reverse_http, web_delivery, fetch)', true ]),
        OptBool.new('HTTP_SSL_PROBE', [ true, 'Also attempt an SSL/TLS HTTP probe (catches reverse_https and HTTPS fetch servers)', true ]),
        OptBool.new('SCAN_UDP', [ true, 'Also probe each port over UDP (catches reverse_udp handlers)', false ]),
        OptBool.new('ECHO_BACK', [ true, 'When a command-shell "echo <token>" probe is seen, echo the token back to verify the shell and capture any follow-up commands', true ]),
        OptFloat.new('ECHO_FOLLOWUP_WAIT', [ true, 'How long (seconds) to keep reading after echoing the token back, to capture AutoRunScript/operator commands', 8 ]),
        OptInt.new('CONCURRENCY', [ true, 'The number of concurrent ports to check per host', 10 ]),
        OptBool.new('DEEP_PROBE', [ true, 'For ports that stay silent, actively elicit passive handlers: open a 2nd connection (ReverseTcpDouble: cmd/unix/reverse, reverse_openssl, reverse_ssl_double_telnet) and send a 16-byte UUID (pingback) to provoke a response', true ])
      ]
    )

    deregister_options('RPORT') # in favor of ports so we can do bulk ones
  end

  def timeout
    datastore['TIMEOUT'].to_f
  end

  # CONCURRENCY drives 1.upto() in run_host, so a value < 1 would spawn zero
  # worker threads and leave the port queue forever unemptied (a silent
  # busy-loop). Reject it up front with the standard option-validation error.
  def validate
    super
    raise Msf::OptionValidateError, ['CONCURRENCY'] if datastore['CONCURRENCY'].to_i < 1
  end

  def validate_ports
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError, ['PORTS'] if ports.empty?

    ports
  end

  def run_host(ip)
    ports = validate_ports

    if datastore['THREADS'].to_i > 1 && datastore['CONCURRENCY'].to_i > 1
      vprint_warning("THREADS (hosts) and CONCURRENCY (ports) multiply: total worker threads can reach ~#{datastore['THREADS'].to_i * datastore['CONCURRENCY'].to_i}")
    end
    # Per-host sink for detected handlers, rendered as one Rex::Text::Table when
    # the port sweep finishes (instead of long single-line hits). Scanner runs
    # run_host on a replicant per host, so this is host-local; the lock guards
    # the concurrent per-port worker threads below.
    @host_results = []
    @host_results_lock = ::Mutex.new

    # Hard per-port deadline (seconds) so one wedged port - e.g. a black-hole TLS
    # handshake - can never stall its whole concurrency batch. It sums the
    # worst-case blocking waits a single port can incur back-to-back:
    #   timeout              -> the initial TCP connect()
    #   3 * FIRST_BYTE_WAIT  -> up to three sequential "wait for the first byte"
    #                           reads on one port: the stage drain, the silent-port
    #                           HTTP/double-handler fallback, and the UDP probe
    #   ECHO_FOLLOWUP_WAIT   -> reading a shell's AutoRunScript output after echo-back
    #   + 5                  -> fixed slack for TLS setup, idle-read tails, scheduling
    # It is deliberately a loose over-estimate (those paths rarely all hit the same
    # port), so the Timeout below only fires for genuinely stuck ports, not merely
    # slow ones. With defaults: 1 + (3 * 5) + 8 + 5 = 29s.
    port_deadline = timeout + (3 * datastore['FIRST_BYTE_WAIT'].to_f) + datastore['ECHO_FOLLOWUP_WAIT'].to_f + 5

    until ports.empty?
      threads = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_port = ports.shift
          break unless this_port

          threads << framework.threads.spawn("Module(#{refname})-#{ip}:#{this_port}", false, this_port) do |port|
            ::Timeout.timeout(port_deadline) do
              check_port(ip, port, timeout) # with deep_prob on handles all protocols but udp. with it turned off only handles tcp
              check_port_udp(ip, port, timeout) if datastore['SCAN_UDP']
            end
          rescue ::Timeout::Error
            vprint_warning("per-port timeout (#{port_deadline.round}s), skipping")
          end
        end
        # Bounded join as a backstop in case Timeout cannot interrupt a blocked call.
        threads.each { |t| t.join(port_deadline + 5) }
      rescue ::Timeout::Error
        # Swallowed: the per-port rescue above already reported the skip, and the
        # ensure still needs to run so a wedged batch cannot leak live threads.
      ensure
        threads.each do |x|
          x.kill
        rescue StandardError
          nil
        end
      end
    end

    print_host_results(ip)
  end

  def check_port(ip, port, timeout)
    sock = nil
    begin
      sock = connect(false,
                     {
                       'RHOST' => ip,
                       'RPORT' => port,
                       'ConnectTimeout' => timeout
                     })
      return unless sock

      buf = drain_stage(sock)
      result = fingerprint(buf)

      if result[:match]
        handle_match(ip, port, 'tcp', result, sock)
      elsif buf.nil? || buf.empty?
        # The server waited for us to speak first. That is the behavior of MSF's
        # HTTP-based handlers (reverse_http/https, web_delivery, fetch servers),
        # so try to fingerprint them over HTTP before giving up.
        http = datastore['HTTP_PROBE'] ? http_fingerprint(sock, ip, port, timeout) : nil
        if http
          report_handler(ip, port, 'tcp', http)
        elsif datastore['DEEP_PROBE'] && (deep = deep_probe(ip, port, sock))
          # deep_probe pairs a second connection (ReverseTcpDouble) / sends a
          # UUID (pingback); our idle first socket was dropped inside it first.
          sock = nil
          report_handler(ip, port, 'tcp', deep)
        else
          vprint_status('Open, no unsolicited data and no Metasploit HTTP fingerprint (stageless reverse shell/meterpreter, or unrelated service)')
        end
      else
        vprint_status("Talks first but does not look like a stage (banner: #{buf[0, 32].inspect})")
      end
    rescue ::Rex::ConnectionRefused
      vprint_status('Connection refused')
    rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error => e
      vprint_status("Connection error (#{e.class})")
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::StandardError => e
      vprint_error("#{e.class} #{e}")
    ensure
      begin
        disconnect(sock)
      rescue StandardError
        nil
      end
    end
  end

  # Actively provoke handlers that stay silent on a single plain connection.
  # Returns a result hash or nil. `idle_sock` is our first (silent) connection,
  # dropped up front so it does not interfere with a double handler's pairing.
  def deep_probe(ip, port, idle_sock)
    begin
      disconnect(idle_sock)
    rescue StandardError
      nil
    end
    paired_connect_probe(ip, port, false) ||
      (datastore['HTTP_SSL_PROBE'] && ssl_paired_probe(ip, port)) ||
      pingback_probe(ip, port) || nil
  end

  # Msf::Handler::ReverseTcpDouble (cmd/unix/reverse, reverse_openssl,
  # reverse_ssl_double_telnet, ...) waits for TWO connections, then writes
  # "echo <token>;" to both to pair them. Open a second connection and read
  # both to elicit that probe.
  def paired_connect_probe(ip, port, ssl)
    socks = []
    2.times do
      socks << connect(false, { 'RHOST' => ip, 'RPORT' => port, 'SSL' => ssl, 'ConnectTimeout' => 3 })
    end
    socks.compact.each do |s|
      fp = fingerprint(drain_stage(s))
      next unless fp[:match]

      detail = ['ReverseTcpDouble paired connections', ('over SSL/TLS' if ssl), fp[:detail]].compact.join('; ')
      return { payload: fp[:payload], detail: detail, framing: fp[:framing], confidence: fp[:confidence], bytes: fp[:bytes] }
    end
    nil
  rescue ::StandardError
    nil
  ensure
    socks.each do |s|
      disconnect(s)
    rescue StandardError
      nil
    end
  end

  # The double-SSL variants need the paired connections over TLS. Bound it with
  # its own deadline (a Rex SSL socket can block on a silent peer).
  def ssl_paired_probe(ip, port)
    ::Timeout.timeout(12) { paired_connect_probe(ip, port, true) }
  rescue ::StandardError
    nil
  end

  # A pingback handler (Msf::Sessions::Pingback) reads up to 16 bytes with a 1s
  # timeout, then closes and sends nothing. Send 16 bytes and confirm the server
  # closes promptly with no reply - a benign silent service would instead leave
  # the read to time out. Low confidence by nature (any service that drops the
  # connection on 16 bytes of junk looks similar).
  def pingback_probe(ip, port)
    s = connect(false, { 'RHOST' => ip, 'RPORT' => port, 'ConnectTimeout' => 3 })
    return nil unless s

    s.put("\x00" * 16)
    t0 = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
    data = begin
      s.get_once(-1, 2)
    rescue ::IOError
      nil
    end
    elapsed = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC) - t0
    return nil unless (data.nil? || data.empty?) && elapsed < 1.0

    {
      payload: 'likely pingback handler',
      detail: 'pingback_reverse_tcp family',
      framing: "handler closed the connection #{elapsed.round(2)}s after a 16-byte write, returning no data (reads a 16-byte UUID then closes)",
      confidence: 'low'
    }
  rescue ::StandardError
    nil
  ensure
    begin
      disconnect(s)
    rescue StandardError
      nil
    end
  end

  # Probe a port over UDP. A reverse_udp handler waits in recvfrom() for any
  # inbound datagram, then sends the stage back, so a single probe datagram
  # elicits the same staging fingerprint as the TCP path.
  def check_port_udp(ip, port, _timeout)
    udp = nil
    begin
      udp = Rex::Socket::Udp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Context' => { 'Msf' => framework, 'MsfExploit' => self }
      )
      udp.put("\x00")
      buf = udp_drain(udp)
      result = fingerprint(buf)
      handle_match(ip, port, 'udp', result, nil) if result[:match]
    rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
      # Swallowed: a refused/filtered/closed UDP port is a non-finding while
      # sweeping, so there is nothing to report and no port worth alarming on.
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::StandardError => e
      vprint_error("(udp) - #{e.class} #{e}")
    ensure
      begin
        udp.close
      rescue StandardError
        nil
      end
    end
  end

  # Report a detected handler and, for command-shell echo probes, optionally
  # echo the token back to verify the shell and capture follow-up commands.
  def handle_match(ip, port, proto, result, sock)
    row = report_handler(ip, port, proto, result)

    return unless result[:echo_token] && datastore['ECHO_BACK'] && sock

    followup = echo_back_capture(sock, result[:echo_token])
    if followup && !followup.empty?
      print_good('Captured follow-up after shell verification (likely AutoRunScript / operator commands):')
      followup.each_line { |line| print_line("      #{line.chomp}") }
      loot_path = store_loot(
        'metasploit.handler.autorunscript',
        'text/plain',
        ip,
        followup,
        "handler_followup_#{port}.txt",
        "Commands an operator's AutoRunScript/InitialAutoRunScript ran against the connecting shell on #{Rex::Socket.to_authority(ip, port)}"
      )
      print_good("Saved captured commands to loot: #{loot_path}")
      report_note(host: ip, port: port, type: 'msf.handler.followup', data: { 'commands' => followup.split("\n").reject(&:empty?), 'loot' => loot_path }, update: :unique_data)
      @host_results_lock.synchronize { row[:notes] = 'AutoRunScript/operator commands captured to loot' }
    else
      vprint_status('No follow-up commands after echo-back (no AutoRunScript configured)')
    end
  end

  # Record a detection in the per-host results sink (printed as a table by
  # print_host_results when the host sweep finishes) and report the service.
  # Returns the row so callers (handle_match) can annotate it afterwards.
  def report_handler(ip, port, proto, result)
    vprint_status("Metasploit handler detected (#{proto}): #{result[:payload]}")
    row = {
      port: port,
      proto: proto,
      payload: result[:payload],
      detail: result[:detail].to_s,
      confidence: result[:confidence],
      bytes: result[:bytes],
      framing: result[:framing],
      notes: ''
    }
    @host_results_lock.synchronize { @host_results << row }
    svc_detail = row[:detail].empty? ? '' : " (#{row[:detail]})"
    report_service(host: ip, port: port, proto: proto, name: 'metasploit-handler', info: "#{result[:payload]}#{svc_detail} | #{result[:framing]} (#{result[:confidence]} confidence)")
    row
  end

  # Render everything report_handler collected for this host as a single table.
  def print_host_results(ip)
    return if @host_results.empty?

    tbl = Rex::Text::Table.new(
      'Header' => "Metasploit payload handlers detected on #{ip} (#{@host_results.length} found)",
      'Indent' => 1,
      'Columns' => ['Port', 'Proto', 'Payload', 'Detail', 'Confidence', 'Bytes', 'Framing', 'Notes']
    )
    @host_results.sort_by { |r| [r[:port], r[:proto]] }.each do |r|
      tbl << [r[:port], r[:proto], r[:payload], r[:detail], r[:confidence], r[:bytes], r[:framing], r[:notes]]
    end
    print_good(tbl.to_s)
  end

  # Echo the verification token back, then keep reading to capture whatever the
  # handler sends next (e.g. an operator's AutoRunScript / InitialAutoRunScript).
  def echo_back_capture(sock, token)
    sock.put("#{token}\n")
    wait = datastore['ECHO_FOLLOWUP_WAIT'].to_f
    idle = datastore['IDLE_TIMEOUT'].to_f

    buf = +''
    chunk = begin
      sock.get_once(-1, wait)
    rescue StandardError
      nil
    end
    return buf if chunk.nil? || chunk.empty?

    buf << chunk
    while buf.length < 65_536
      chunk = begin
        sock.get_once(-1, idle)
      rescue StandardError
        nil
      end
      break if chunk.nil? || chunk.empty?

      buf << chunk
    end
    buf
  rescue ::StandardError
    buf
  end

  # UDP equivalent of drain_stage using recvfrom (which returns [data, host, port]).
  def udp_drain(udp)
    first_wait = datastore['FIRST_BYTE_WAIT'].to_f
    idle_wait = datastore['IDLE_TIMEOUT'].to_f
    max_bytes = datastore['MAX_STAGE_SIZE'].to_i

    buf = +''
    data, = udp.recvfrom(65_535, first_wait)
    return buf if data.nil? || data.empty?

    buf << data
    while buf.length < max_bytes
      data, = udp.recvfrom(65_535, idle_wait)
      break if data.nil? || data.empty?

      buf << data
    end
    buf
  end

  # Read whatever the server sends unprompted, up to MAX_STAGE_SIZE.
  def drain_stage(sock)
    first_wait = datastore['FIRST_BYTE_WAIT'].to_f
    idle_wait = datastore['IDLE_TIMEOUT'].to_f
    max_bytes = datastore['MAX_STAGE_SIZE'].to_i

    buf = +''
    chunk = begin
      sock.get_once(-1, first_wait)
    rescue StandardError
      nil
    end
    return buf if chunk.nil? || chunk.empty?

    buf << chunk
    while buf.length < max_bytes
      chunk = begin
        sock.get_once(-1, idle_wait)
      rescue StandardError
        nil
      end
      break if chunk.nil? || chunk.empty?

      buf << chunk
    end
    buf
  end

  # Fingerprint MSF's HTTP-based handlers. Tries a plaintext request on the
  # already-open socket first, then (optionally) an SSL request on a fresh
  # connection for reverse_https / HTTPS fetch servers. Returns a result hash
  # or nil.
  def http_fingerprint(sock, ip, port, _timeout)
    result = http_classify(http_exchange(sock), scheme: 'http')
    return result if result

    return nil unless datastore['HTTP_SSL_PROBE']

    ssl_sock = nil
    begin
      # The Rex connect timeout only bounds the TCP connect, not the TLS
      # handshake read - so wrap the whole SSL probe in its own short deadline
      # to keep a stalled handshake from eating the per-port budget.
      ::Timeout.timeout(9) do
        ssl_sock = connect(false,
                           {
                             'RHOST' => ip,
                             'RPORT' => port,
                             'SSL' => true,
                             'ConnectTimeout' => 3
                           })
        # A single GET-and-read handles every SSL-fronted MSF handler:
        #   * reverse_https answers our request with the default "It works!" page
        #   * shell_reverse_tcp_ssl ignores the request and sends its unsolicited
        #     "echo <token>" shell-verification probe over TLS
        #   * reverse_tcp_ssl (staged) has already pushed its stage on connect
        # so send the request, then classify the reply as HTTP, then as a raw
        # stage/echo. (A Rex SSL socket's get_once does not honor its read timeout
        # against a silent peer, so we must speak first rather than blind-peek.)
        raw = http_exchange(ssl_sock)
        hc = http_classify(raw, scheme: 'https')
        if hc
          hc
        elsif raw && !raw.empty? && (fp = fingerprint(raw))[:match]
          { payload: fp[:payload], detail: "over SSL/TLS; #{fp[:detail]}", framing: fp[:framing], confidence: fp[:confidence], bytes: fp[:bytes], echo_token: fp[:echo_token] }
        end
      end
    rescue ::StandardError => e
      vprint_error("SSL probe failed: #{e.class} #{e}")
      nil
    ensure
      begin
        disconnect(ssl_sock)
      rescue StandardError
        nil
      end
    end
  end

  # Send a GET for a random path and return the raw HTTP response, or nil.
  def http_exchange(sock)
    return nil unless sock

    path = '/' + Rex::Text.rand_text_alphanumeric(8..16)
    host = begin
      sock.peerhost
    rescue StandardError
      'localhost'
    end
    req = "GET #{path} HTTP/1.1\r\nHost: #{host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    sock.put(req)

    # An HTTP/TLS server that is going to answer answers fast; cap the wait so a
    # non-answer (e.g. a plaintext GET to a TLS port) fails in ~2s, not 5s+.
    first_wait = [datastore['FIRST_BYTE_WAIT'].to_f, 2.0].min
    idle_wait = datastore['IDLE_TIMEOUT'].to_f
    buf = +''
    chunk = sock.get_once(-1, first_wait)
    return nil if chunk.nil? || chunk.empty?

    buf << chunk
    while buf.length < 65_536
      chunk = begin
        sock.get_once(-1, idle_wait)
      rescue StandardError
        nil
      end
      break if chunk.nil? || chunk.empty?

      buf << chunk
    end
    buf
  rescue ::StandardError
    nil
  end

  # Classify a raw HTTP response against known MSF HTTP-server signatures.
  def http_classify(raw, scheme: 'http')
    return nil if raw.nil? || raw.empty?
    return nil unless raw =~ %r{\AHTTP/1\.[01]\s+(\d{3})}

    code = ::Regexp.last_match(1).to_i
    server = raw[/^Server:[ \t]*(.+?)\r?$/i, 1].to_s.strip
    body = raw.partition("\r\n\r\n").last
    server_str = server.empty? ? '(none)' : server

    # reverse_http(s) Meterpreter handler answers 200 OK with the default
    # "It works!" body to ANY unknown URI (real servers would 404).
    if code == 200 && body.include?('It works!')
      return {
        payload: "reverse_#{scheme} Meterpreter handler",
        detail: "#{scheme.upcase} transport",
        framing: %(200 OK + default "It works!" body on an unknown URI; Server: #{server_str}),
        confidence: 'high'
      }
    end

    # Rex HTTP server (web_delivery, fetch handler, exploit module servers)
    # returns a distinctive 404 page on unknown URIs.
    if body.include?('was not found on this server') && body.include?('<h1>Not found</h1>')
      return {
        payload: 'Metasploit Rex HTTP server',
        detail: 'web_delivery / fetch handler / exploit module server',
        framing: "Rex 404 page on unknown URI; Server: #{server_str}",
        confidence: 'high'
      }
    end

    nil
  end

  # Classify the unsolicited data using the staging-protocol framing.
  #
  # The strongest, most reliable signal is "the 4-byte length the server
  # declared up front was actually delivered" (body.length >= declared length).
  # A benign service that happens to talk first will not satisfy this: a short
  # text banner produces an enormous bogus length, and a service streaming lots
  # of data is astronomically unlikely to have its first 4 bytes equal the
  # number of bytes that follow. Note metsrv appends a config block after the
  # stage, so body.length is frequently *larger* than the declared length.
  def fingerprint(buf)
    return { match: false } if buf.nil? || buf.empty?

    bytes = buf.length
    return { match: false } if bytes < 8

    body = buf[4..] || +''
    l_le = buf[0, 4].unpack1('V')
    l_be = buf[0, 4].unpack1('N')

    # 1. Command-shell handler echo probe. Msf::Sessions::CommandShell#bootstrap
    #    verifies a reverse shell by sending "echo <rand_alphanumeric(8..24)>".
    #    Catches stageless/staged reverse *shell* handlers that talk first.
    if (md = buf.match(/\Aecho ([A-Za-z0-9]{8,24});?\s*\z/))
      return {
        match: true,
        payload: 'command shell handler',
        # detail: 'reverse shell - "echo" verification probe',
        framing: 'unsolicited "echo <token>" shell-verification command',
        confidence: 'high',
        bytes: bytes,
        echo_token: md[1]
      }
    end

    # 2. Python staged: big-endian length prefix + base64(zlib(...)) text stage.
    #    The prefix must be a plausible stage length: a benign base64 text blob
    #    reads its four leading ASCII bytes as a 700M+ "length", far outside the
    #    plausible range, while a real stage declares its exact base64 size.
    #    Only the declared l_be bytes are the stage - handlers can append a
    #    binary tail after it (a plain-TCP python handler sends ~400 extra
    #    bytes), so slice to the declared length or those stages fall through
    #    to the generic big-endian branch below.
    if plausible_stage_len?(l_be) && base64_stage?(body[0, l_be])
      confidence = (body.length >= l_be) ? 'high' : 'medium'
      return {
        match: true,
        payload: 'python/meterpreter/reverse_tcp',
        detail: 'base64/zlib staged',
        framing: "4-byte big-endian length prefix (declared #{l_be}, #{bytes} bytes received); base64/zlib stage",
        confidence: confidence,
        bytes: bytes
      }
    end

    # 3. Native staged, little-endian length prefix (Windows family).
    if plausible_stage_len?(l_le) && body.length >= l_le
      return {
        match: true,
        **windows_payload_guess(l_le),
        framing: "4-byte little-endian length prefix (declared #{l_le}, #{bytes} bytes received)",
        confidence: 'high',
        bytes: bytes
      }
    end

    # 4. Native staged, big-endian length prefix but not base64 (php/java/uncommon).
    if plausible_stage_len?(l_be) && body.length >= l_be
      return {
        match: true,
        **big_endian_payload_guess(body),
        framing: "4-byte big-endian length prefix (declared #{l_be}, #{bytes} bytes received)",
        confidence: 'medium',
        bytes: bytes
      }
    end

    # 5. Small unix execve stage (linux/bsd staged shell). These send raw
    #    /bin/sh shellcode with no length prefix, below the binary-burst floor.
    #    Gated to small buffers so large meterpreter stages (which may embed
    #    "/bin/sh") fall through to the generic native-stage branch instead.
    if bytes < 4096 && (buf.include?('/bin/sh') || buf.include?('//sh'))
      return {
        match: true,
        payload: 'native staged unix shell',
        detail: 'execve /bin/sh shellcode, e.g. linux/*/shell/reverse_tcp',
        framing: "raw execve shellcode stage, no length prefix (#{bytes} bytes)",
        confidence: 'medium',
        bytes: bytes
      }
    end

    # 5b. Raw x86 stager shellcode with no length prefix. Legacy Windows stagers
    #     (reverse_nonx_tcp, reverse_ord_tcp, and the *_nonx/_ord shell, vncinject
    #     and patchupmeterpreter variants) push the stage as bare shellcode of only
    #     ~200-260 bytes starting with the classic block_api prelude (0xFC = cld)
    #     rather than a 4-byte length prefix, so they sit just under the generic
    #     binary-burst floor below. A benign text service cannot start with 0xFC.
    if bytes >= 48 && buf.b.start_with?("\xFC".b) && printable_ratio(buf) < 0.9
      return {
        match: true,
        payload: 'Windows staged payload - raw stager shellcode',
        detail: 'e.g. reverse_nonx_tcp/reverse_ord_tcp/shell',
        framing: "raw x86 stager shellcode, no length prefix (#{bytes} bytes, 0xFC prelude)",
        confidence: 'medium',
        bytes: bytes
      }
    end

    # 6. Raw stage with no length prefix (Linux/OSX native), an RC4-encrypted
    #    stage, or an encrypted stageless handler stream. Either way the server
    #    volunteered a burst of non-text data unprompted, which is highly abnormal
    #    for a benign service. The 128-byte floor still clears short binary banners
    #    while catching the small (~240B) RC4 and legacy stager bursts.
    if bytes >= 128 && printable_ratio(buf) < 0.75
      return {
        match: true,
        payload: 'native staged meterpreter or encrypted/stageless handler',
        detail: 'linux/osx native stage',
        framing: "no length prefix; #{bytes} bytes of unsolicited binary data",
        confidence: 'low',
        bytes: bytes
      }
    end

    { match: false }
  end

  # Refine a big-endian length-prefixed stage into its source family by content.
  # Returns the payload/detail fields for the result hash.
  def big_endian_payload_guess(body)
    sample = body[0, 65_536].to_s
    if sample.include?('<?php') || sample.include?('eval(')
      { payload: 'php/meterpreter/reverse_tcp', detail: 'php staged' }
    elsif sample.include?("PK\x03\x04") || sample.include?('META-INF')
      # Java and Android (Dalvik) both stage a jar/dex with a BE length prefix.
      { payload: 'java or android meterpreter', detail: 'JVM/Dalvik jar staged' }
    else
      { payload: 'staged payload with big-endian length prefix', detail: 'python/php/java family' }
    end
  end

  # True if the body looks like a base64-encoded (python/php) stage and is long
  # enough that a short text banner won't be mistaken for one.
  def base64_stage?(body)
    return false if body.nil? || body.length < 32

    body.match?(%r{\A[A-Za-z0-9+/=\r\n]+\z})
  end

  def plausible_stage_len?(len)
    len.between?(16, 16 * 1024 * 1024)
  end

  # Best-effort arch/payload guess for windows native stages based on stage size.
  # Returns the payload/detail fields for the result hash.
  def windows_payload_guess(stage_len)
    if stage_len < 8192
      { payload: 'windows staged shell/exec', detail: 'small native stage, e.g. windows/shell/reverse_tcp' }
    elsif stage_len > 200_000
      { payload: 'windows/x64/meterpreter/reverse_tcp', detail: 'x64 native staged' }
    else
      { payload: 'windows/meterpreter/reverse_tcp', detail: 'x86 native staged' }
    end
  end

  def printable_ratio(str)
    return 0.0 if str.nil? || str.empty?

    str.count("\x20-\x7e\t\r\n").to_f / str.length
  end
end
