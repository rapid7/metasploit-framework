##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntp'
require 'securerandom'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Fuzzer
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Scanner

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
        OptInt.new('SLEEP', [true, 'Sleep for this many ms between requests', 0]),
        OptInt.new('WAIT', [true, 'Wait this many ms for responses', 250])
      ])

    register_advanced_options(
      [
        OptString.new('VERSIONS', [false, 'Specific versions to fuzz (csv)', '2,3,4']),
        OptString.new('MODES', [false, 'Modes to fuzz (csv)']),
        OptString.new('MODE_6_OPERATIONS', [false, 'Mode 6 operations to fuzz (csv)']),
        OptString.new('MODE_7_IMPLEMENTATIONS', [false, 'Mode 7 implementations to fuzz (csv)']),
        OptString.new('MODE_7_REQUEST_CODES', [false, 'Mode 7 request codes to fuzz (csv)'])
      ])
  end

  def sleep_time
    datastore['SLEEP'] / 1000.0
  end

  def check_and_set(setting)
    thing = setting.upcase
    const_name = thing.to_sym
    var_name = thing.downcase
    if datastore[thing]
      instance_variable_set("@#{var_name}", datastore[thing].split(/[^\d]/).select { |v| !v.empty? }.map { |v| v.to_i })
      unsupported_things = instance_variable_get("@#{var_name}") - Rex::Proto::NTP.const_get(const_name)
      fail "Unsupported #{thing}: #{unsupported_things}" unless unsupported_things.empty?
    else
      instance_variable_set("@#{var_name}", Rex::Proto::NTP.const_get(const_name))
    end
  end

  def run_host(ip)
    # check and set the optional advanced options
    check_and_set('VERSIONS')
    check_and_set('MODES')
    check_and_set('MODE_6_OPERATIONS')
    check_and_set('MODE_7_IMPLEMENTATIONS')
    check_and_set('MODE_7_REQUEST_CODES')

    connect_udp
    fuzz_version_mode(ip, true)
    fuzz_version_mode(ip, false)
    fuzz_short(ip)
    fuzz_random(ip)
    fuzz_control(ip) if @modes.include?(6)
    fuzz_private(ip) if @modes.include?(7)
    disconnect_udp
  end

  # Sends a series of NTP control messages
  def fuzz_control(host)
    @versions.each do |version|
      print_status("#{host}:#{rport} fuzzing version #{version} control messages (mode 6)")
      @mode_6_operations.each do |op|
        request = Rex::Proto::NTP.ntp_control(version, op).to_binary_s
        what = "#{request.size}-byte version #{version} mode 6 op #{op} message"
        vprint_status("#{host}:#{rport} probing with #{request.size}-byte #{what}")
        responses = probe(host, datastore['RPORT'].to_i, request)
        handle_responses(host, request, responses, what)
        Rex.sleep(sleep_time)
      end
    end
  end

  # Sends a series of NTP private messages
  def fuzz_private(host)
    @versions.each do |version|
      print_status("#{host}:#{rport} fuzzing version #{version} private messages (mode 7)")
      @mode_7_implementations.each do |implementation|
        @mode_7_request_codes.each do |request_code|
          request = Rex::Proto::NTP.ntp_private(version, implementation, request_code, "\0" * 188).to_binary_s
          what = "#{request.size}-byte version #{version} mode 7 imp #{implementation} req #{request_code} message"
          vprint_status("#{host}:#{rport} probing with #{request.size}-byte #{what}")
          responses = probe(host, datastore['RPORT'].to_i, request)
          handle_responses(host, request, responses, what)
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
      what = "short #{request.size}-byte random message"
      vprint_status("#{host}:#{rport} probing with #{what}")
      responses = probe(host, datastore['RPORT'].to_i, request)
      handle_responses(host, request, responses, what)
      Rex.sleep(sleep_time)
    end
  end

  # Sends a series of random, full-sized datagrams, looking for a reply
  def fuzz_random(host)
    print_status("#{host}:#{rport} fuzzing random messages")
    0.upto(5) do
      # TODO: is there a better way to pick this size?  Should more than one be tried?
      request = SecureRandom.random_bytes(48)
      what = "random #{request.size}-byte message"
      vprint_status("#{host}:#{rport} probing with #{what}")
      responses = probe(host, datastore['RPORT'].to_i, request)
      handle_responses(host, request, responses, what)
      Rex.sleep(sleep_time)
    end
  end

  # Sends a series of different version + mode combinations
  def fuzz_version_mode(host, short)
    print_status("#{host}:#{rport} fuzzing #{short ? 'short ' : nil}version and mode combinations")
    @versions.each do |version|
      @modes.each do |mode|
        request = Rex::Proto::NTP::NTPGeneric.new
        request.version = version
        request.mode = mode
        unless short
          # TODO: is there a better way to pick this size?  Should more than one be tried?
          request.payload = SecureRandom.random_bytes(16)
        end
        request = request.to_binary_s
        what = "#{request.size}-byte #{short ? 'short ' : nil}version #{version} mode #{mode} message"
        vprint_status("#{host}:#{rport} probing with #{what}")
        responses = probe(host, datastore['RPORT'].to_i, request)
        handle_responses(host, request, responses, what)
        Rex.sleep(sleep_time)
      end
    end
  end

  # Sends +message+ to +host+ on UDP port +port+, returning all replies
  def probe(host, port, message)
    message = message.to_binary_s if message.respond_to?('to_binary_s')
    replies = []
    begin
      udp_sock.sendto(message, host, port, 0)
    rescue ::Errno::EISCONN
      udp_sock.write(message)
    end
    reply = udp_sock.recvfrom(65535, datastore['WAIT'] / 1000.0)
    while reply && reply[1]
      replies << reply
      reply = udp_sock.recvfrom(65535, datastore['WAIT'] / 1000.0)
    end
    replies
  end

  def handle_responses(host, request, responses, what)
    problems = []
    descriptions = []
    request = request.to_binary_s if request.respond_to?('to_binary_s')
    responses.select! { |r| r[1] }
    return if responses.empty?
    responses.each do |response|
      data = response[0]
      descriptions << Rex::Proto::NTP.describe(data)
      problems << 'large response' if request.size < data.size
      ntp_req = Rex::Proto::NTP::NTPGeneric.new.read(request)
      ntp_resp = Rex::Proto::NTP::NTPGeneric.new.read(data)
      problems << 'version mismatch' if ntp_req.version != ntp_resp.version
    end

    problems << 'multiple responses' if responses.size > 1
    problems.sort!
    problems.uniq!

    description = descriptions.join(',')
    if problems.empty?
      vprint_status("#{host}:#{rport} -- Received '#{description}' to #{what}")
    else
      print_good("#{host}:#{rport} -- Received '#{description}' to #{what}: #{problems.join(',')}")
    end
  end
end
