##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'        => 'John the Ripper Password Cracker (Fast Mode)',
      'Description' => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired as hashed files (loot) or raw LANMAN/NTLM hashes (hashdump). The goal
        of this module is to find trivial passwords in a short amount of time. To
        crack complex passwords or use large wordlists, John the Ripper should be
        used outside of Metasploit. This initial version just handles LM/NTLM credentials
        from hashdump and uses the standard wordlist and rules.
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    cracker = new_john_cracker

    # generate our wordlist and close the file handle
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path
    cracker.hash_path = hash_file

    ['lm','nt'].each do |format|
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = format
      print_status "Cracking #{format} hashes in normal wordlist mode..."
      # Turn on KoreLogic rules if the user asked for it
      if datastore['KoreLogic']
        cracker_instance.rules = 'KoreLogicRules'
        print_status "Applying KoreLogic ruleset..."
      end
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracking #{format} hashes in single mode..."
      cracker_instance.rules = 'single'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      if format == 'lm'
        print_status "Cracking #{format} hashes in incremental mode (All4)..."
        cracker_instance.rules = nil
        cracker_instance.wordlist = nil
        cracker_instance.incremental = 'All4'
        cracker_instance.crack do |line|
          print_status line.chomp
        end
      end

      print_status "Cracking #{format} hashes in incremental mode (Digits)..."
      cracker_instance.rules = nil
      cracker_instance.wordlist = nil
      cracker_instance.incremental = 'Digits'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracked Passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?

        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >=7
        username = fields.shift
        core_id = fields.pop

        # pop off dead space here
        2.times{ fields.pop }

        # get the NT and LM hashes
        nt_hash = fields.pop
        lm_hash = fields.pop
        password = fields.join(':')

        if format == 'lm'
          if password.blank?
            if nt_hash == Metasploit::Credential::NTLMHash::BLANK_NT_HASH
              password = ''
            else
              next
            end
          end
          password = john_lm_upper_to_ntlm(password, nt_hash)
          # password can be nil if the hash is broken (i.e., the NT and
          # LM sides don't actually match) or if john was only able to
          # crack one half of the LM hash. In the latter case, we'll
          # have a line like:
          #  username:???????WORD:...:...:::
          next if password.nil?
        end

        print_good "#{username}:#{password}:#{core_id}"
        create_cracked_credential( username: username, password: password, core_id: core_id)
      end
    end
  end

  def hash_file
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NTLMHash').each do |core|
      user = core.public.username
      hash_string = core.private.data
      id = core.id
      hashlist.puts "#{user}:#{id}:#{hash_string}:::#{id}"
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    hashlist.path
  end
end
