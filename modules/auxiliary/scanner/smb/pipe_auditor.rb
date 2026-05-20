##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::SMB::Client::PipeAuditor

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB Session Pipe Auditor',
      'Description' => 'Determine what named pipes are accessible over SMB',
      'Author' => 'hdm',
      'License' => MSF_LICENSE,
    )
  end

  def connect(*args, **kwargs)
    super(*args, **kwargs, direct: @smb_direct)
  end

  def rport
    @rport
  end

  # Fingerprint a single host
  def run_host(ip)
    pipes = []

    if session
      print_status("Using existing session #{session.sid}")
      @rport = datastore['RPORT'] = session.port
      self.simple = session.simple_client
      self.simple.connect("\\\\#{session.address}\\IPC$")
      report_pipes(ip, check_pipes)
    else
      if datastore['RPORT'].blank? || datastore['RPORT'] == 0
        smb_services = [
          { port: 445, direct: true },
          { port: 139, direct: false }
        ]
      else
        smb_services = [
          { port: datastore['RPORT'], direct: datastore['SMBDirect'] }
        ]
      end

      smb_services.each do |smb_service|
        @rport = smb_service[:port]
        @smb_direct = smb_service[:direct]

        begin
          connect
          smb_login
          pipes += check_pipes
          disconnect
          report_pipes(ip, pipes)
        rescue Rex::Proto::SMB::Exceptions::SimpleClientError, Rex::ConnectionError => e
          vprint_error("SMB client Error with RPORT=#{@rport} SMBDirect=#{@smb_direct}: #{e.to_s}")
        end
      end
    end
  end

  def check_pipes
    pipes = []
    check_named_pipes.each do |pipe_name, _|
      pipes.push(pipe_name)
    end
    pipes
  end

  def report_pipes(ip, pipes)
    if (pipes.length > 0)
      print_good("Pipes: #{pipes.join(", ")}")
      # Add Report
      report_note(
        :host	=> ip,
        :proto => 'tcp',
        :sname	=> 'smb',
        :port	=> rport,
        :type	=> 'Pipes Found',
        :data	=> { :pipes => pipes.join(", ") }
      )
    end
  end

end
