##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'            => 'John the Ripper Linux Password Cracker',
      'Description'     => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from unshadowed passwd files from Unix systems. The module will only crack
        MD5 and DES implementations by default. Set Crypt to true to also try to crack
        Blowfish and SHA implementations. Warning: This is much slower.
      },
      'Author'          =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'         => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )

    register_options(
      [
        OptBool.new('Crypt',[false, 'Try crypt() format hashes(Very Slow)', false])
      ]
    )

  end

  def run

    formats = [ 'md5crypt', 'descrypt', 'bsdicrypt']
    if datastore['Crypt']
      formats << 'crypt'
    end

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

    formats.each do |format|
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

      print_status "Cracked Passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >=7
        username = fields.shift
        core_id  = fields.pop
        4.times { fields.pop }
        password = fields.join('') # Anything left must be the password. This accounts for passwords with : in them
        print_good password_line
        create_cracked_credential( username: username, password: password, core_id: core_id)
      end
    end
  end

  def hash_file
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      if core.private.jtr_format =~ /md5|des|bsdi|crypt/
        user = core.public.username
        hash_string = core.private.data
        id = core.id
        hashlist.puts "#{user}:#{hash_string}:::::#{id}:"
      end
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    hashlist.path
  end



end
