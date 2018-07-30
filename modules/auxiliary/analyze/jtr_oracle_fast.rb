##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'           => 'John the Ripper Oracle Password Cracker (Fast Mode)',
      'Description'    => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from the oracle_hashdump module. Passwords that have been successfully
        cracked are then saved as proper credentials
      },
      'Author'         =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'        => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    cracker = new_john_cracker

    # generate our wordlist and close the file handle
    wordlist = wordlist_file
    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path
    #cracker.hash_path = hash_file("des")

    ['oracle', 'oracle11'].each do |format|
      cracker_instance = cracker.dup
      cracker_instance.format = format

      case format
        when 'oracle'
          cracker_instance.hash_path = hash_file('des')
        when 'oracle11'
          cracker_instance.hash_path = hash_file('raw-sha1')
      end

      print_status "Cracking #{format} hashes in normal wordlist mode..."
      # Turn on KoreLogic rules if the user asked for it
      if datastore['KoreLogic']
        cracker_instance.rules = 'KoreLogicRules'
        print_status "Applying KoreLogic ruleset..."
      end
      print_status "Crack command #{cracker_instance.crack_command.join(' ')}"
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracking #{format} hashes in single mode..."
      cracker_instance.rules = 'single'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracked passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >=3
        username = fields.shift
        core_id  = fields.pop
        password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them

        # Postgres hashes always prepend the username to the password before hashing. So we strip the username back off here.
        password.gsub!(/^#{username}/,'')
        print_good "#{username}:#{password}:#{core_id}"
        create_cracked_credential( username: username, password: password, core_id: core_id)
      end
    end

  end


  def hash_file(format)
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      if core.private.jtr_format =~ /#{format}/
        user = core.public.username
        hash_string = core.private.data.split(':')[1]
        id = core.id
        hashlist.puts "#{user}:#{hash_string}:#{id}:"
      end
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    hashlist.path
  end
end
