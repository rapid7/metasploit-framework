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

    # since a dynamic list doesn't include an ID, we keep a local list to include it
    # for lookup at a later time
    reconstruct_list = []
    # create the hash file first, so if there aren't any hashes we can quit early
    cracker.hash_path, reconstruct_list = hash_file(reconstruct_list)

    # generate our wordlist and close the file handle
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end
    wordlist.close

    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path

    cleanup_files = [cracker.hash_path, wordlist.path]

    ['dynamic_1034'].each do |format|
      cracker_instance = cracker.dup
      # the following line is left for historical purposes, however
      # while psql uses MD5, instead of using a format flag to john
      # we actually just set the 'dynamic_1034' type in the hashes
      # file directly
      cracker_instance.format = format
      print_status "Cracking #{format} hashes in normal wordlist mode..."
      # Turn on KoreLogic rules if the user asked for it
      if datastore['KORELOGIC']
        cracker_instance.rules = 'KoreLogicRules'
        print_status "Applying KoreLogic ruleset..."
      end
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracking #{format} hashes in single mode..."
      cracker_instance.rules = 'single'
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracking #{format} hashes in incremental mode (Digits)..."
      cracker_instance.rules = nil
      cracker_instance.wordlist = nil
      cracker_instance.incremental = 'Digits'
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracked passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >=2
        username = fields.shift
        #core_id  = fields.pop #not passed in on dynamic formats
        password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them

        # this is ugly, we need to get the id, however it isnt in the john files
        # we generated.  So we have to open the john.pot file to get the hash
        # to password matching, so the end product looks like this:
        # (reconstruct_list) (john.pot)        (cracked)
        #    un        /----> hash              un
        #    hash ----/       password -------> password
        #    id
        # example .pot dynamic_1034 line: $dynamic_1034$be86a79bf2043622d58d5453c47d4860$HEX$24556578616d706c65:password
        # also note how the $HEX$ till : part is added by jtr
        pot = File.open(cracker.john_pot_file, 'rb')
        pots = pot.read
        pot.close
        # here we combine un:hash and hash:password to make un:hash:password
        combined = []
        pots.each_line do |p|
          reconstruct_list.each do |r|
            hash = r.split(":")[1]
              next unless p.starts_with?("#{hash}$HEX$")
              combined << "#{r}:#{p.split(':')[1]}"
          end
        end
        combined.each do |cred|
          c = cred.split(":")
          c_u = c[0].strip
          c_h = c[1].strip
          c_i = c[2].strip
          c_p = c[3].strip
          next unless c_u==username && c_p==password
          print_good "#{username}:#{password}"
          create_cracked_credential( username: username, password: password, core_id: c_i)
        end
      end
    end
    if datastore['DeleteTempFiles']
      cleanup_files.each do |f|
        File.delete(f)
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

  def hash_file(reconstruct_list)
    wrote_hash = false
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::PostgresMD5').each do |core|
      if core.private.jtr_format =~ /postgres|raw-md5/
        @username_set << core.public.username
        hash = hash_to_jtr(core)
        hashlist.puts hash
        hash = hash.split('$dynamic_1034$')[1]
        reconstruct_list << "#{core.public.username}:$dynamic_1034$#{hash}:#{core.id}"
        wrote_hash = true
      end
    end
    hashlist.close
    unless wrote_hash # check if we wrote anything and bail early if we didn't
      hashlist.delete
      fail_with Failure::NotFound, 'No Postgres hashes in database to crack'
    end
    print_status "Hashes written out to #{hashlist.path}"
    return hashlist.path, reconstruct_list
  end
end
