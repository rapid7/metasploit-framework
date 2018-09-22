##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary

  #Included to grab the john.pot and use some utiltiy functions
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
        'Name'           => 'John the Ripper Postgres SQL Password Cracker',
        'Description'    => %Q{
          This module uses John the Ripper to attempt to crack Postgres password
          hashes, gathered by the postgres_hashdump module. It is slower than some of the other
          JtR modules because it has to do some wordlist manipulation to properly handle postgres'
          format.
      },
        'Author'         => ['theLightCosine'],
        'License'        => MSF_LICENSE
    )

  end

  def run
    @username_set = Set.new

    cracker = new_john_cracker

    hash_list = hash_file

    # generate our wordlist and close the file handle
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close


    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path
    cracker.hash_path = hash_list

    ['raw-md5'].each do |format|
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

      print_status "Cracking #{format} hashes in incremental mode (Digits)..."
      cracker_instance.incremental = 'Digits'
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

  # Override the mixin method to add prependers
  def wordlist_file
    return nil unless framework.db.active
    wordlist = Metasploit::Framework::JtR::Wordlist.new(
        prependers: @username_set,
        custom_wordlist: datastore['CUSTOM_WORDLIST'],
        mutate: datastore['MUTATE'],
        use_creds: datastore['USE_CREDS'],
        use_db_info: datastore['USE_DB_INFO'],
        use_default_wordlist: datastore['USE_DEFAULT_WORDLIST'],
        use_hostnames: datastore['USE_HOSTNAMES'],
        use_common_root: datastore['USE_ROOT_WORDS'],
        workspace: myworkspace
    )
    wordlist.to_file
  end

  def hash_file
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::PostgresMD5').each do |core|
      if core.private.jtr_format =~ /des/
        user = core.public.username
        @username_set << user
        hash_string = core.private.data
        hash_string.gsub!(/^md5/, '')
        id = core.id
        hashlist.puts "#{user}:#{hash_string}:#{id}:"
      end
    end
    hashlist.close
    print_status "Hashes written out to #{hashlist.path}"
    hashlist.path
  end
end
