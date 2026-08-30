# -*- coding: binary -*-

# Linux post-exploitation helpers for file and credential reporting.
module Msf::Post::Linux
  def report_linux_hashdump(passwd_file, shadow_file)
    unless passwd_file.nil? || passwd_file.empty?
      p = store_loot('linux.passwd', 'text/plain', session, passwd_file, 'passwd.tx', 'Linux Passwd File')
      vprint_good("passwd saved in: #{p}")
    end

    unless shadow_file.nil? || shadow_file.empty?
      p = store_loot('linux.shadow', 'text/plain', session, shadow_file, 'shadow.tx', 'Linux Password Shadow File')
      vprint_good("Shadow saved in: #{p}")
    end

    john_file = unshadow(passwd_file.to_s, shadow_file.to_s)
    return if john_file == ''

    john_file.each_line do |l|
      hash_parts = l.split(':')
      next if hash_parts[1].nil? || hash_parts[1].empty?
      next if hash_parts[1].start_with?('!')
      next if hash_parts[1] == '*'

      jtr_format = Metasploit::Framework::Hashes.identify_hash hash_parts[1]

      if jtr_format.empty?
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

    upasswd = store_loot('linux.hashes', 'text/plain', session, john_file, 'unshadowed_passwd.pwd', 'Linux Unshadowed Password File')
    print_good("Unshadowed Password File: #{upasswd}")
  end

  def unshadow(pf, sf)
    unshadowed = ''
    sf.each_line do |sl|
      pass = sl.scan(/^[^:]+:([^:]*)/).join

      next if pass.nil? || pass.empty?
      next if pass.start_with?('!')
      next if pass == '*'

      user = sl.scan(/(^[^:]+):/).join
      pf.each_line do |pl|
        next unless pl.match(/^#{user}:/)

        unshadowed << pl.gsub(':x:', ":#{pass}:")
      end
    end

    unshadowed
  end
end
