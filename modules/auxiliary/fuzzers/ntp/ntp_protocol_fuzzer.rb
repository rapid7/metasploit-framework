##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'bit-struct'
require 'securerandom'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Fuzzer
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Scanner

  NTP_VERSIONS = (0..7).to_a
  NTP_MODES = (0..7).to_a

  def initialize
    super(
      'Name'        => 'NTP Protocol Fuzzer',
      'Description' => %q(
        A simplistic fuzzer for the Network Time Protocol that sends the
        following probes to understand NTP and look for anomalous NTP behavior:

        * All possible combinations of NTP versions and modes, even if not
          allowed or specified in the RFCs
        * Short versions of the above
        * Short, invalid datagrams
        * Full-size, random datagrams
        * All possible NTP control messages
        * All possible NTP private messages

        This findings of this fuzzer are not necessarily indicative of bugs,
        let alone vulnerabilities, rather they point out interesting things
        that might deserve more attention.  Furthermore, this module is not
        particularly intelligent and there are many more areas of NTP that
        could be explored, including:

        * Warn if the response is 100% identical to the request
        * Warn if the "mode" (if applicable) doesn't align with what we expect,
        * Filter out the 12-byte mode 6 unsupported opcode errors.
        * Fuzz the control message payload offset/size/etc.  There be bugs
      ),
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(123),
        OptString.new('VERSIONS', [true, 'Versions to fuzz', NTP_VERSIONS.join(',')]),
        OptString.new('MODES', [true, 'Versions to fuzz', NTP_MODES.join(',')]),
        OptInt.new('SLEEP', [true, 'Sleep for this many ms between requests', 0]),
        OptInt.new('WAIT', [true, 'Wait this many ms for responses', 500])
      ], self.class)
  end

  # A very generic NTP message
  #
  # Uses the common/similar parts from versions 1-4 and considers everything
  # after to be just one big field.  For the particulars on the different versions,
  # see:
  #   http://tools.ietf.org/html/rfc958#appendix-B
  #   http://tools.ietf.org/html/rfc1059#appendix-B
  #   pages 45/48 of http://tools.ietf.org/pdf/rfc1119.pdf
  #   http://tools.ietf.org/html/rfc1305#appendix-D
  #   http://tools.ietf.org/html/rfc5905#page-19
  class NTPGeneric < BitStruct
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |LI | VN  | mode|    Stratum    |      Poll     |   Precision   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :li, 2,  default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 0
    unsigned :stratum, 8,  default: 0
    unsigned :poll, 8,  default: 0
    unsigned :precision, 8,  default: 0
    char :payload, 352
  end

  # An NTP control message.  Control messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPControl < BitStruct
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |00 | VN  |   6 |R E M|  op     |     Sequence                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              status           |      association id           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              offset           |     count                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :reserved, 2, default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 6
    unsigned :response, 1,  default: 0
    unsigned :error, 1,  default: 0
    unsigned :more, 1,  default: 0
    unsigned :operation, 5,  default: 0
    unsigned :sequence, 16,  default: 0
    unsigned :status, 16,  default: 0
    unsigned :association_id, 16,  default: 0
    # TODO: there *must* be bugs in the handling of these next two fields!
    unsigned :payload_offset, 16,  default: 0
    unsigned :payload_size, 16,  default: 0
    rest :payload
  end

  # An NTP "private" message.  Private messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPPrivate < BitStruct
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |00 | VN  |   7 |A|                   Sequence                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Implementation| request code  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :reserved, 2, default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 7
    unsigned :auth, 1, default: 0
    unsigned :sequence, 7, default: 0
    unsigned :implementation, 8, default: 0
    unsigned :request_code, 8, default: 0
    rest :payload
  end

  def build_ntp_control(version, operation, payload = nil)
    n = NTPControl.new
    n.version = version
    n.operation = operation
    if payload
      n.payload_offset = 0
      n.payload_size = payload.size
      n.payload = payload
    end
    n.to_s
  end

  def build_ntp_private(version, implementation, request_code, payload = nil)
    n = NTPPrivate.new
    n.version = version
    n.implementation = implementation
    n.request_code = request_code
    n.payload = payload if payload
    n.to_s
  end

  def build_ntp_generic(version, mode)
    n = NTPGeneric.new
    n.version = version
    n.mode = mode
    n.to_s
  end

  def sleep_time
    datastore['SLEEP'] / 1000.0
  end

  def run_host(ip)
    # parse and sanity check versions
    @versions = datastore['VERSIONS'].split(/[^\d]/).select { |v| !v.empty? }.map { |v| v.to_i }
    unsupported_versions = @versions - NTP_VERSIONS
    fail "Unsupported NTP versions: #{unsupported_versions}" unless unsupported_versions.empty?
    # parse and sanity check modes
    @modes = datastore['MODES'].split(/[^\d]/).select { |m| !m.empty? }.map { |v| v.to_i }
    unsupported_modes = @modes - NTP_MODES
    fail "Unsupported NTP modes: #{unsupported_modes}" unless unsupported_modes.empty?

    connect_udp
    fuzz_version_mode(ip)
    fuzz_version_mode(ip, true)
    fuzz_short(ip)
    fuzz_random(ip)
    fuzz_control(ip) if @modes.include?(6)
    fuzz_private(ip) if @modes.include?(7)
    disconnect_udp
  end

  # Sends a series of NTP control messages
  def fuzz_control(host)
    print_status("#{host}:#{rport} fuzzing control messages (mode 6)")
    @versions.map { |v| v.to_i }.each do |version|
      0.upto(31) do |op|
        request = build_ntp_control(version, op)
        what = "#{request.size}-byte version #{version} mode 6 op #{op} message"
        vprint_status("#{host}:#{rport} probing with #{request.size}-byte #{what}")
        probe(host, datastore['RPORT'].to_i, request).each do |reply|
          handle_response(host, request, reply, what)
        end
        Rex.sleep(sleep_time)
      end
    end
  end

  # Sends a series of NTP private messages
  def fuzz_private(host)
    print_status("#{host}:#{rport} fuzzing private messages (mode 7)")
    @versions.map { |v| v.to_i }.each do |version|
      0.upto(255) do |implementation|
        0.upto(255) do |request_code|
          request = build_ntp_private(version, implementation, request_code)
          what = "#{request.size}-byte version #{version} mode 7 imp #{implementation} req #{request_code} message"
          vprint_status("#{host}:#{rport} probing with #{request.size}-byte #{what}")
          probe(host, datastore['RPORT'].to_i, request).each do |reply|
            handle_response(host, request, reply, what)
          end
          Rex.sleep(sleep_time)
        end
      end
    end
  end

  # Sends a series of small, short datagrams, looking for a reply
  def fuzz_short(host)
    print_status("#{host}:#{rport} fuzzing short messages")
    0.upto(4) do |size|
      request = SecureRandom.random_bytes(size)
      what = "Short #{request.size}-byte random message"
      vprint_status("#{host}:#{rport} probing with #{what}")
      probe(host, datastore['RPORT'].to_i, request).each do |reply|
        handle_response(host, request, reply, what)
      end
      Rex.sleep(sleep_time)
    end
  end

  # Sends a series of random, full-sized datagrams, looking for a reply
  def fuzz_random(host)
    print_status("#{host}:#{rport} fuzzing random messages")
    0.upto(5) do
      request = SecureRandom.random_bytes(48)
      what = "random #{request.size}-byte message"
      vprint_status("#{host}:#{rport} probing with #{what}")
      probe(host, datastore['RPORT'].to_i, request).each do |reply|
        handle_response(host, request, reply, what)
      end
      Rex.sleep(sleep_time)
    end
  end

  # Sends a series of different version + mode combinations
  def fuzz_version_mode(host, short=false)
    print_status("#{host}:#{rport} fuzzing #{short ? 'short ' : nil}version and mode combinations")
    @versions.map { |v| v.to_i }.each do |version|
      @modes.map { |m| m.to_i }.each do |mode|
        request = build_ntp_generic(version, mode)
        request = request[0, 4] if short
        what = "#{request.size}-byte #{short ? 'short ' : nil}version #{version} mode #{mode} message"
        vprint_status("#{host}:#{rport} probing with #{what}")
        probe(host, datastore['RPORT'].to_i, request).each do |reply|
          handle_response(host, request, reply, what)
        end
        Rex.sleep(sleep_time)
      end
    end
  end

  # Sends +message+ to +host+ on UDP port +port+, returning all replies
  def probe(host, port, message)
    replies = []
    udp_sock.sendto(message, host, port, 0)
    while (r = udp_sock.recvfrom(65535, datastore['WAIT'] / 1000.0) and r[1])
      replies << r
    end
    replies
  end

  # Parses the given message and provides a description about the NTP message inside
  def describe(message)
    ntp = NTPGeneric.new(message)
    "#{message.size}-byte version #{ntp.version} mode #{ntp.mode} reply"
  end

  def handle_response(host, request, response, what)
    return unless response[1]
    data = response[0]
    problems = []
    problems << 'large response' if request.size < data.size
    ntp_req = NTPGeneric.new(request)
    ntp_resp = NTPGeneric.new(data)
    problems << 'version mismatch' if ntp_req.version != ntp_resp.version

    if problems.empty?
      print_status("#{host}:#{rport} -- Received #{describe(data)} to #{what}")
    else
      print_good("#{host}:#{rport} -- Received #{describe(data)} to #{what}: #{problems.join(',')}")
    end
  end
end
