# -*- coding: binary -*-

require 'concurrent'

module Msf
module Sessions

###
#
# Quectel modem session - concrete Msf::Sessions::Modem subclass backed by
# the Driver / Connection AT-command serial driver defined here.
#
# Routing capability:
#   TCP client - AT+QIOPEN "TCP"  (create_tcp_client_channel)
#   UDP client - AT+QIOPEN "UDP"  (create_udp_channel)
#   TCP server - not supported    (create_tcp_server_channel raises)
#
###
class Modem
  class Quectel < Modem

    # Tracks one AT command until completion (OK/ERROR/SEND FAIL)
    class CmdWaiter
      attr_reader :cmd, :event, :buf
      attr_accessor :ok

      def initialize(cmd)
        @cmd   = cmd
        @event = Concurrent::Event.new
        @buf   = []
        @ok    = false
      end
    end

    # Represents one opened modem socket (SID)
    class Connection
      attr_reader :sock_id, :recv_queue, :prompt_event, :ack_event
      attr_accessor :ack_ok, :open_event, :open_ok, :open_err, :prompt_ok, :closed_flag

      def initialize(modem, sock_id)
        @modem        = modem
        @sock_id      = sock_id
        @recv_queue   = Queue.new      # payload chunks or nil EOF sentinel
        @prompt_event = Concurrent::Event.new
        @ack_event    = Concurrent::Event.new
        @ack_ok       = false
        @prompt_ok    = true
        @closed_flag  = false
        @close_mutex  = Mutex.new
        @open_event   = Concurrent::Event.new
        @open_ok      = false
        @open_err     = nil
      end

      # Send data over this modem socket via AT+QISEND.
      #
      # Data is automatically broken into chunks no larger than
      # @modem.cfg[:max_chunk_size] (default 1024 B). Quectel modems accept at
      # most 1460 B per AT+QISEND invocation; TLS records can be up to 16 KB so
      # chunking is required for HTTPS / any binary protocol.
      def send(data)
        raise_closed! if closed?

        chunk_size = [@modem.cfg[:max_chunk_size], 1].max
        offset = 0
        while offset < data.bytesize
          raise_closed! if closed?

          chunk = data.byteslice(offset, chunk_size)
          send_chunk(chunk)
          offset += chunk.bytesize
        end
      end

      private

      # Send a single chunk (<= max_chunk_size bytes) via one AT+QISEND transaction.
      def send_chunk(data)
        @modem.at_lock.synchronize do
          raise_closed! if closed?

          at = "AT+QISEND=#{@sock_id},#{data.bytesize}\r"

          begin
            @modem.mutex.synchronize do
              raise_closed! if closed?

              @prompt_ok = true
              @prompt_event.reset
              @ack_event.reset
              @modem.pending_send_sid = @sock_id
              @modem.serial.write(at)
            end

            # Wait for '>' prompt (or early reject)
            unless @prompt_event.wait(@modem.cfg[:prompt_timeout])
              raise ::Rex::RuntimeError, "[SID #{@sock_id}] No '>' prompt for QISEND"
            end
            @prompt_event.reset
            raise_closed! if closed?

            unless @prompt_ok
              raise ::Rex::RuntimeError, "[SID #{@sock_id}] QISEND rejected (no prompt)"
            end

            # Write payload + Ctrl-Z
            @modem.mutex.synchronize do
              raise_closed! if closed?

              @modem.serial.write(data)
              @modem.serial.write("\x1A")
            end

            # Wait for SEND OK/FAIL
            unless @ack_event.wait(@modem.cfg[:ack_timeout])
              raise ::Rex::RuntimeError, "[SID #{@sock_id}] No SEND OK/ERROR"
            end
            @ack_event.reset
            raise_closed! if closed?

            unless @ack_ok
              raise ::Rex::RuntimeError, "[SID #{@sock_id}] SEND ERROR"
            end
          ensure
            @modem.pending_send_sid = nil if @modem.pending_send_sid == @sock_id
          end
        end
      end

      public

      # Blocking recv; returns:
      #   - bytes (String) when payload available
      #   - nil when modem closed socket
      def recv
        @recv_queue.pop(true)
      rescue ::ThreadError
        return nil if closed?

        @recv_queue.pop
      end

      def push_payload(data)
        return if closed?

        @recv_queue << data
      end

      def closed?
        @close_mutex.synchronize { @closed_flag }
      end

      def mark_closed
        @modem.release_id(@sock_id) if transition_closed
      end

      def close
        should_qiclose = transition_closed

        if should_qiclose && !@modem.closed?
          begin
            @modem.send_at("AT+QICLOSE=#{@sock_id},0", @modem.cfg[:cmd_timeout])
          rescue ::StandardError => e
            @modem.log_debug("[SID #{@sock_id}] QICLOSE error: #{e.class} #{e.message}")
          end
        end
        @modem.release_id(@sock_id) if should_qiclose
      end

      private

      def raise_closed!
        raise ::IOError, "[SID #{@sock_id}] Socket has been closed."
      end

      def transition_closed
        notify_close = false
        @close_mutex.synchronize do
          unless @closed_flag
            @closed_flag = true
            notify_close = true
          end
          @prompt_ok = false
          @ack_ok = false
        end
        @prompt_event.set
        @ack_event.set
        @recv_queue << nil if notify_close
        notify_close
      end
    end

    # Encapsulates serial I/O and URC parsing for the Quectel module.
    #
    # Initialization only opens the port, configures termios, and starts the
    # background reader thread. The caller is responsible for the startup
    # sequence (AT probe, ATE0, leftover-socket cleanup, health watchdog) so
    # that it can interleave its own status output between steps.
    class Driver
      attr_reader :serial, :mutex, :cfg
      attr_accessor :pending_send_sid
      attr_reader :at_lock
      attr_reader :open_lock

      # Serial port configuration uses Linux-specific termios ioctls (TCGETS/TCSETSW).
      def self.supported_platform?
        RUBY_PLATFORM.include?('linux')
      end

      # -----------------------------------------------------------------------
      # Linux termios constants for in-process serial port configuration.
      # Source: asm-generic/ioctls.h and asm-generic/termbits.h (NCCS=19).
      # Using ioctl avoids shelling out to stty.
      # -----------------------------------------------------------------------
      TCGETS        = 0x5401  # get termios struct
      TCSETSW       = 0x5403  # drain then apply termios struct
      TERMIOS_SIZE  = 36      # sizeof(struct termios): 4*uint32 + 1 + 19*uint8

      # Baud-rate values encoded in c_cflag (B* constants)
      BAUD_CONSTANTS = {
         9_600 => 0x0000_000D,
        19_200 => 0x0000_000E,
        38_400 => 0x0000_000F,
        57_600 => 0x0000_1001,
       115_200 => 0x0000_1002,
       230_400 => 0x0000_1003,
       460_800 => 0x0000_1004,
       921_600 => 0x0000_1007,
      }.freeze

      CBAUD   = 0x0000_100F  # baud-rate mask in c_cflag
      CSIZE   = 0x0000_0030  # character-size mask
      CS8     = 0x0000_0030  # 8-bit characters
      CSTOPB  = 0x0000_0040  # 2 stop bits (clear = 1 stop bit)
      CREAD   = 0x0000_0080  # enable receiver
      PARENB  = 0x0000_0100  # parity enable
      CRTSCTS = 0x8000_0000  # RTS/CTS hardware flow control

      # c_iflag bits cleared by cfmakeraw
      IFLAG_RAW_CLEAR = 0x0001 |  # IGNBRK
                        0x0002 |  # BRKINT
                        0x0008 |  # PARMRK
                        0x0020 |  # ISTRIP
                        0x0040 |  # INLCR
                        0x0080 |  # IGNCR
                        0x0100 |  # ICRNL
                        0x0400 |  # IXON
                        0x1000    # IXOFF
      OPOST  = 0x0000_0001  # output processing (sole c_oflag bit we clear)

      # c_lflag bits cleared by cfmakeraw
      LFLAG_RAW_CLEAR = 0x0001 |  # ISIG  - no signal generation (no Ctrl-C etc.)
                        0x0002 |  # ICANON - line-by-line processing off
                        0x0008 |  # ECHO
                        0x0010 |  # ECHOE
                        0x0020 |  # ECHOK
                        0x0040 |  # ECHONL
                        0x8000    # IEXTEN

      VTIME_IDX = 5   # c_cc index: read timeout (tenths of a second)
      VMIN_IDX  = 6   # c_cc index: minimum bytes before read returns

      def initialize(port, baud, framework, cfg)
        @framework = framework
        @serial = ::File.open(port, 'r+b')
        @serial.sync = true

        configure_serial_port(@serial, baud)

        @cfg = cfg

        @mutex        = Mutex.new    # serialize direct writes/reads as needed
        @cmd_mutex    = Mutex.new
        @at_lock      = Mutex.new    # serialize all AT commands (prevents interleaving)
        @pending_cmds = []           # FIFO of CmdWaiter

        @line_buf    = ''.b
        @reader_stop = false
        @rdy_event   = Concurrent::Event.new

        # Serialize QIOPEN operations (one open in-flight at a time)
        @open_lock        = Mutex.new
        @pending_send_sid = nil

        @id_mutex = Mutex.new
        @free_ids = (0...@cfg[:modem_sockets]).to_a
        @conns    = {}              # sid -> Connection

        @modem_ready       = true
        @ready_mutex       = Mutex.new
        @health_fail_count = 0
        @health_stop       = false
        @closed = false

        # Spawn dedicated reader thread
        @reader_thread = @framework.threads.spawn('cellular_modem_reader', false) do
          reader_loop
        end

      rescue ::Exception
        # Stop background threads that may have been spawned before the failure.
        close
        raise
      end

      # === readiness/health helpers =====================================

      def closed?
        @closed
      end

      def modem_ready?
        @ready_mutex.synchronize { @modem_ready }
      end

      def set_modem_ready(val, reason: nil)
        changed = false
        @ready_mutex.synchronize do
          if @modem_ready != val
            @modem_ready = val
            changed = true
          end
        end
        return unless changed

        msg = val ? "[MODEM] READY#{reason ? " (#{reason})" : ''}" \
                  : "[MODEM] NOT READY#{reason ? " (#{reason})" : ''}"
        val ? ilog(msg, 'cellular_modem') : wlog(msg, 'cellular_modem')
      end

      # Poll AT until the modem responds with OK, up to total_timeout_s seconds
      # (0 = no timeout). Raises Rex::TimeoutError if the deadline is exceeded.
      def startup_wait_for_ok(total_timeout_s, interval_s, probe_timeout_s)
        total_timeout_s = total_timeout_s.to_i
        interval_s = interval_s.to_f
        interval_s = 1.0 if interval_s <= 0

        # total_timeout_s == 0 means "no timeout" (wait indefinitely until AT returns OK)
        deadline = (total_timeout_s > 0) ? (::Time.now + total_timeout_s) : nil

        loop do
          if deadline && ::Time.now > deadline
            set_modem_ready(false, reason: 'startup probe timed out')
            raise ::Rex::TimeoutError, "Startup AT probe timed out after #{total_timeout_s}s"
          end

          begin
            send_at('AT', probe_timeout_s)
            set_modem_ready(true, reason: 'startup probe OK')
            return
          rescue ::Rex::TimeoutError, ::Rex::RuntimeError
            # modem not ready yet - keep polling
          rescue ::StandardError => e
            log_debug("startup AT probe error: #{e.class} #{e.message}")
          end

          ::Rex.sleep(interval_s)
        end
      end

      # Wait up to +timeout+ seconds for the RDY URC. Best-effort; returns
      # true if seen, false if the modem was already past the boot banner.
      def wait_for_rdy(timeout)
        @rdy_event.wait(timeout)
      end

      def start_health_watchdog
        @health_stop = false
        @health_thread = @framework.threads.spawn('cellular_modem_health_watchdog', false) do
          loop do
            break if @health_stop
            begin
              # Probe modem liveness
              send_at('AT', @cfg[:healthcheck_timeout])
              @health_fail_count = 0

              # If we were previously NOT READY, run minimal re-init (echo off) after reboot
              unless modem_ready?
                reinitialize_after_reboot
                set_modem_ready(true, reason: 'health probe OK')
              end
            rescue ::Rex::TimeoutError, ::Rex::RuntimeError
              @health_fail_count += 1
              if @health_fail_count >= @cfg[:healthcheck_max_fails]
                set_modem_ready(false, reason: "health probe failed #{@health_fail_count}x")
              end
            rescue ::StandardError => e
              @health_fail_count += 1
              log_debug("health probe exception: #{e.class} #{e.message}")
              if @health_fail_count >= @cfg[:healthcheck_max_fails]
                set_modem_ready(false, reason: "health probe exception #{@health_fail_count}x")
              end
            end
            ::Rex.sleep(@cfg[:healthcheck_interval])
          end
        end
      end

      def reinitialize_after_reboot
        # After a power cycle, the module often resets settings like echo.
        # If echo is enabled, the modem will echo QISEND payload bytes back on the AT port,
        # which can look like "binary URCs" in the console. Re-assert ATE0 once we're back.
        begin
          send_at('ATE0', @cfg[:cmd_timeout])
        rescue ::StandardError => e
          log_debug("reinitialize_after_reboot: ATE0 failed: #{e.class} #{e.message}")
        end

        # Best-effort drain any buffered garbage that may have accumulated during reboot.
        begin
          loop do
            r, _w, _e = ::IO.select([@serial], nil, nil, 0)
            break unless r && r.include?(@serial)
            @serial.read_nonblock(4096)
          end
        rescue ::IO::WaitReadable, ::EOFError, ::IOError
        end
      end

      def close
        return if @closed

        @closed = true
        @health_stop = true
        @reader_stop = true
        conns = []
        if @id_mutex && @conns
          @id_mutex.synchronize do
            conns = @conns.values
            @conns.clear
            @free_ids = (0...@cfg[:modem_sockets]).to_a if @free_ids && @cfg
          end
        else
          conns = @conns&.values || []
          @conns&.clear
        end
        conns.each(&:mark_closed)

        begin
          @serial.close if @serial
        rescue ::IOError
        end

        stop_thread(@health_thread)
        stop_thread(@reader_thread)
      end

      def log_debug(msg)
        dlog(msg, 'cellular_modem')
      end

      private

      def stop_thread(thread)
        return unless thread
        return if thread == ::Thread.current

        thread.join(1)
        return unless thread.alive?

        thread.kill
        thread.join
      end

      # Configure the serial port in-process using termios ioctls.
      # Equivalent to: stty raw -echo -crtscts -ixon -ixoff cs8 <baud>
      #
      # Raises Errno::ENOTTY if +io+ is not a serial device.
      def configure_serial_port(io, baud)
        baud_bits = BAUD_CONSTANTS[baud] or
          raise ::ArgumentError, "Unsupported baud rate: #{baud}. " \
                "Valid rates: #{BAUD_CONSTANTS.keys.join(', ')}"

        buf = ("\x00" * TERMIOS_SIZE).b
        io.ioctl(TCGETS, buf)

        c_iflag, c_oflag, c_cflag, c_lflag = buf.unpack('LLLL')
        c_cc = buf[17, 19].bytes

        # cfmakeraw: disable all special character and line-discipline processing
        c_iflag  = (c_iflag  & ~IFLAG_RAW_CLEAR) & 0xFFFF_FFFF
        c_oflag  = (c_oflag  & ~OPOST)           & 0xFFFF_FFFF
        c_lflag  = (c_lflag  & ~LFLAG_RAW_CLEAR) & 0xFFFF_FFFF
        c_cflag  = (c_cflag  & ~(CSIZE | PARENB | CRTSCTS | CSTOPB)) & 0xFFFF_FFFF
        c_cflag |= (CS8 | CREAD)

        # Set baud rate (encoded in c_cflag for the old-style termios ABI)
        c_cflag = (c_cflag & (~CBAUD & 0xFFFF_FFFF)) | baud_bits

        # VMIN=1, VTIME=0: reads block until at least one byte arrives
        c_cc[VMIN_IDX]  = 1
        c_cc[VTIME_IDX] = 0

        buf[0, 16]  = [c_iflag, c_oflag, c_cflag, c_lflag].pack('LLLL')
        buf[17, 19] = c_cc.pack('C*')

        io.ioctl(TCSETSW, buf)
      end

      public

      # --- SID pool management ---

      def allocate_id
        @id_mutex.synchronize do
          sid = @free_ids.shift
          raise ::RuntimeError, 'No socket IDs available' unless sid

          sid
        end
      end

      def release_id(sid)
        return unless sid

        @id_mutex.synchronize do
          @conns.delete(sid)
          @free_ids << sid unless @free_ids.include?(sid)
        end
      end

      def register_connection(sid, conn)
        @id_mutex.synchronize do
          @conns[sid] = conn
        end
      end

      def connection_for_id(sid)
        @id_mutex.synchronize do
          @conns[sid]
        end
      end

      #
      # Open an outbound TCP socket through the Quectel modem.
      #
      # @param host [String] remote IP address or hostname
      # @param port [Integer] remote TCP port
      # @return [Connection, nil] nil on timeout or error
      def open_tcp_client_socket(host, port)
        open_socket('TCP', host, port, 'open_tcp_connection')
      end

      #
      # Open an outbound UDP socket through the Quectel modem.
      #
      # @param host [String] remote IP address or hostname
      # @param port [Integer] remote UDP port
      # @return [Connection, nil] nil on timeout or error
      def open_udp_socket(host, port)
        open_socket('UDP', host, port, 'open_udp_connection')
      end

      def open_socket(protocol, host, port, error_method)
        @open_lock.synchronize do
          sid = allocate_id
          conn = Connection.new(self, sid)
          register_connection(sid, conn)

          begin
            cmd = %Q{AT+QIOPEN=1,#{sid},"#{protocol}","#{host}",#{port},0,1}
            send_at(cmd, @cfg[:cmd_timeout])

            unless conn.open_event.wait(@cfg[:open_timeout])
              wlog("[SID #{sid}] #{protocol} QIOPEN timeout", 'cellular_modem')
              release_id(sid)
              return nil
            end

            unless conn.open_ok
              wlog("[SID #{sid}] #{protocol} QIOPEN failed err=#{conn.open_err}", 'cellular_modem')
              release_id(sid)
              return nil
            end

            conn
          rescue ::StandardError => e
            elog("#{error_method} error (sid=#{sid}): #{e.class} #{e.message}", 'cellular_modem')
            release_id(sid)
            nil
          end
        end
      end
      private :open_socket

      # --- AT helper with CmdWaiter ---

      def send_at(cmd, timeout = nil)
        timeout ||= @cfg[:cmd_timeout]
        @at_lock.synchronize do
          waiter = CmdWaiter.new(cmd)
          @cmd_mutex.synchronize do
            @pending_cmds << waiter
          end

          log_debug("-> AT #{cmd}")
          @mutex.synchronize do
            @serial.write("#{cmd}\r")
          end

          unless waiter.event.wait(timeout)
            @cmd_mutex.synchronize do
              @pending_cmds.delete(waiter)
            end
            raise ::Rex::TimeoutError, "AT cmd timeout: #{cmd}"
          end

          waiter.buf.each do |l|
            log_debug("<- #{l}")
          end

          unless waiter.ok
            raise ::Rex::RuntimeError, "AT cmd error: #{cmd}"
          end

          waiter.buf.join("\n")
        end
      end

      # --- Reader loop and line handler ---

      def reader_loop
        loop do
          break if @reader_stop
          ch = nil
          begin
            ch = @serial.read(1)
          rescue ::EOFError, ::IOError => e
            elog("serial read error: #{e.class} #{e.message}", 'cellular_modem')
            break
          end
          next unless ch
          # QISEND '>' prompt (single char, no CRLF)
          if ch == '>'
            sid = @pending_send_sid
            if sid
              conn = connection_for_id(sid)
              if conn
                conn.prompt_ok = true
                conn.prompt_event.set
              end
            end
            next
          end
          @line_buf << ch
          if @line_buf.end_with?("\r\n")
            line = @line_buf.strip
            @line_buf.clear
            handle_line(line)
          end
        end
      end

      def handle_line(line)
        # Avoid spewing raw binary to the console (can happen if echo is re-enabled after reboot)
        if line.bytes.any? { |b| b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F }
          hex = line.bytes.first(32).map { |b| format('%02X', b) }.join(' ')
          log_debug("URC: [binary #{line.bytesize} bytes] #{hex}#{line.bytesize > 32 ? ' ...' : ''}")
        else
          log_debug("URC: #{line}")
        end

        # Boot ready
        if line == 'RDY'
          dlog('[URC] RDY', 'cellular_modem')
          @rdy_event.set
          return
        end

        if line =~ /(POWERED DOWN|POWER DOWN|NORMAL POWER DOWN)/i
          wlog("[URC] #{line}", 'cellular_modem')
          set_modem_ready(false, reason: line)
          return
        end

        # First, feed pending command waiter if any
        @cmd_mutex.synchronize do
          if (waiter = @pending_cmds.first)
            case line
            when 'OK'
              waiter.buf << 'OK'
              waiter.ok  = true
              waiter.event.set
              @pending_cmds.shift
            when /^ERROR/, 'SEND FAIL'
              waiter.buf << line
              waiter.ok  = false
              waiter.event.set
              @pending_cmds.shift
            else
              waiter.buf << line
            end
          end
        end

        # +QIOPEN: sid,err
        if line.start_with?('+QIOPEN:')
          begin
            rest = line.split(':', 2)[1].strip
            parts = rest.split(',').map(&:strip)
            sid  = parts[0].to_i
            err  = parts[1].to_i
            if (conn = connection_for_id(sid))
              conn.open_ok  = (err == 0)
              conn.open_err = err
              conn.open_event.set
            end
          rescue ::StandardError
          end
          return
        end

        # +QIURC: "recv",sid,len
        if line.start_with?('+QIURC: "recv"')
          begin
            parts = line.split(',')
            sid   = parts[1].to_i
            len   = parts[2].to_i
          rescue ::StandardError
            return
          end

          payload = ''.b
          while payload.bytesize < len
            begin
              chunk = @serial.read(len - payload.bytesize)
            rescue ::EOFError, ::IOError
              break
            end
            next unless chunk
            payload << chunk
          end

          if (conn = connection_for_id(sid))
            conn.push_payload(payload)
          end
          return
        end

        # +QIURC: "closed",sid
        if line.start_with?('+QIURC: "closed"')
          begin
            sid = line.split(',')[1].to_i
          rescue ::StandardError
            return
          end
          if (conn = connection_for_id(sid))
            conn.mark_closed
          end
          return
        end

        # QISEND results / early rejects mapped via pending_send_sid
        if ['SEND OK', 'SEND FAIL', 'ERROR'].include?(line)
          sid = @pending_send_sid
          if sid && (conn = connection_for_id(sid))
            ok = (line == 'SEND OK')
            conn.ack_ok = ok
            conn.ack_event.set

            # If the modem rejects QISEND before issuing a '>' prompt, wake the sender
            # that's blocked waiting on prompt_event.
            if !ok && line == 'ERROR'
              conn.prompt_ok = false
              conn.prompt_event.set
            end
          end
          return
        end
      end
    end

    def initialize(quectel_modem, opts = {})
      super(opts)
      @quectel_modem = quectel_modem
      self.info = desc
    end

    def desc
      'Quectel modem'
    end

    def tunnel_to_s
      @quectel_modem.serial.path
    end

    def cleanup
      super # closes all open channels (base Modem#cleanup)
    ensure
      begin
        @quectel_modem&.close
      rescue ::StandardError => e
        elog("Quectel modem cleanup error: #{e.class} #{e.message}", 'cellular_modem')
      end
    end

    # Quectel supports native UDP via AT+QIOPEN "UDP".
    def supports_udp?
      true
    end

    protected

    #
    # Open an outbound TCP connection through the Quectel modem.
    #
    # Sends AT+QIOPEN and waits for the +QIOPEN URC. The connection timeout
    # is governed by the module's OPEN_TIMEOUT_MS datastore option (default
    # 30 s), configured when Driver was constructed.
    #
    # @return [lsock] the local socket end for the framework
    # @raise [Rex::ConnectionError] on open failure or timeout
    #
    def create_tcp_client_channel(params)
      validate_unbound_socket!(params)

      conn = @quectel_modem.open_tcp_client_socket(params.peerhost, params.peerport)
      unless conn
        raise ::Rex::ConnectionError.new(params.peerhost, params.peerport,
          reason: 'Quectel modem failed to open AT connection (QIOPEN timeout or error).')
      end

      chan = TcpClientChannel.new(self, @channel_ticker += 1, conn, params)
      chan.lsock
    end

    #
    # Quectel AT commands do not support inbound TCP listeners.
    #
    def create_tcp_server_channel(params)
      raise ::Rex::ConnectionError.new(params.localhost, params.localport,
        reason: 'TCP server sockets are not supported by Quectel modem sessions.')
    end

    #
    # Open an outbound UDP socket through the Quectel modem via AT+QIOPEN "UDP".
    #
    # @return [lsock] the local UDP socket end for the framework
    # @raise [Rex::ConnectionError] on open failure or timeout
    #
    def create_udp_channel(params)
      validate_unbound_socket!(params)

      conn = @quectel_modem.open_udp_socket(params.peerhost, params.peerport)
      unless conn
        raise ::Rex::ConnectionError.new(params.peerhost, params.peerport,
          reason: 'Quectel modem failed to open UDP AT connection (QIOPEN timeout or error).')
      end

      chan = UdpChannel.new(self, @channel_ticker += 1, conn, params)
      chan.lsock
    end

    def validate_unbound_socket!(params)
      local_addr = params.localhost
      local_port = params.localport.to_i
      bound_addr = local_addr.present? && (!Rex::Socket.is_ip_addr?(local_addr) || Rex::Socket.addr_atoi(local_addr) != 0)
      return unless bound_addr || local_port != 0

      raise ::Rex::BindFailed.new(local_addr, local_port,
        reason: 'Quectel modem sockets do not support binding to a particular address.')
    end
  end
end

end  # Sessions
end  # Msf
