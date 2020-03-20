##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/password_cracker'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/analyze/jtr_mssql_fast'
  moved_from 'auxiliary/analyze/jtr_mysql_fast'
  moved_from 'auxiliary/analyze/jtr_oracle_fast'
  moved_from 'auxiliary/analyze/jtr_postgres_fast'

  def initialize
    super(
      'Name'            => 'Password Cracker: Databases',
      'Description'     => %Q{
          This module uses John the Ripper or Hashcat to identify weak passwords that have been
        acquired from the mssql_hashdump, mysql_hashdump, postgres_hashdump, or oracle_hashdump modules.
        Passwords that have been successfully cracked are then saved as proper credentials.
        Due to the complexity of some of the hash types, they can be very slow.  Setting the
        ITERATION_TIMEOUT is highly recommended.
      },
      'Author'          =>
        [
          'theLightCosine',
          'hdm',
          'h00die' # hashcat integration
        ] ,
      'License'         => MSF_LICENSE,  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
      'Actions'         =>
        [
          ['john', {'Description' => 'Use John the Ripper'}],
          ['hashcat', {'Description' => 'Use Hashcat'}],
        ],
      'DefaultAction' => 'john',
    )

    register_options(
      [
        OptBool.new('MSSQL',[false, 'Include MSSQL hashes', true]),
        OptBool.new('MYSQL',[false, 'Include MySQL hashes', true]),
        OptBool.new('ORACLE',[false, 'Include Oracle hashes', true]),
        OptBool.new('POSTGRES',[false, 'Include Postgres hashes', true]),
        OptBool.new('INCREMENTAL',[false, 'Run in incremental mode', true]),
        OptBool.new('WORDLIST',[false, 'Run in wordlist mode', true])
      ]
    )

  end

  def show_command(cracker_instance)
    return unless datastore['ShowCommand']
    if action.name == 'john'
      cmd = cracker_instance.john_crack_command
    elsif action.name == 'hashcat'
      cmd = cracker_instance.hashcat_crack_command
    end
    print_status("   Cracking Command: #{cmd.join(' ')}")
  end

  def print_results(tbl, cracked_hashes)
    cracked_hashes.each do |row|
      unless tbl.rows.include? row
        tbl << row
      end
    end
    tbl.to_s
  end

  def run
    def process_crack(results, hashes, cred, hash_type, method)
      return results if cred['core_id'].nil? # make sure we have good data
      # make sure we dont add the same one again
      if results.select {|r| r.first == cred['core_id']}.empty?
        results << [cred['core_id'], hash_type, cred['username'], cred['password'], method]
      end

      create_cracked_credential( username: cred['username'], password: cred['password'], core_id: cred['core_id'])
      results
    end

    def check_results(passwords, results, hash_type, hashes, method, cracker)
      passwords.each do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        if action.name == 'john'
          cred = {}
          # we branch here since postgres (dynamic_1034) doesn't include the core_id
          if ['dynamic_1034'].include? hash_type
            next unless fields.count >=2
            cred['username'] = fields.shift
            cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
            cred['core_id'] = nil
            # we now need to read the pot file to pull the original hash to match it back up successfully
            pot = File.open(cracker.john_pot_file, 'rb')
            pots = pot.read
            pot.close
            # here we combine un:hash and hash:password to make un:hash:password
            combined = []
            pots.each_line do |p|
              next unless p.starts_with?('$dynamic_1034$')
              hashes.each do |h|
                next unless p.starts_with? "#{h['hash'].split(':')[1]}$HEX$"
                cred['core_id'] = h['id']
                break
              end
            end
          else
            #mysql*, mssql*, oracle*
            next unless fields.count >=3
            cred['username'] = fields.shift
            cred['core_id']  = fields.pop
            cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
          end
          results = process_crack(results, hashes, cred, hash_type, method)
        elsif action.name == 'hashcat'
          next unless fields.count >= 2
          case hash_type
          when 'dynamic_1034'
            # for postgres we get 3 fields, hash:un:pass.
            hash = fields.shift
            username = fields.shift
            password = fields.join(':')
          when 'oracle11', 'raw-sha1,oracle'
            hash = "#{fields.shift}#{fields.shift}" # we pull the first two fields, hash, and salt
            password = fields.join(':')
          else
            hash = fields.shift
            password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them
          end

          next if hash.include?("Hashfile '") && hash.include?("' on line ") # skip error lines

          hashes.each do |h|
            case hash_type
            when 'mssql05','mssql12', 'mysql'
              # mssql\d\d comes back as 0x then the rest uppercase, so we need to upcase everything to match correctly
              next unless h['hash'].upcase == hash.upcase
            when 'mssql'
              # for whatever reason hashcat zeroes out part of the hash in --show.
              # show: 0x0100a607ba7c0000000000000000000000000000000000000000b6d6261460d3f53b279cc6913ce747006a2e3254:FOO
              # orig: 0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254
              hash_zero_format = "#{h['hash'][0..13]}#{'0'*40}#{h['hash'][54..hash.length]}".upcase
              next unless hash_zero_format == hash.upcase
            when 'mysql-sha1'
              # add the * back to the beginning to match up and fix casing
              next unless h['hash'] == "*#{hash}".upcase
            when 'oracle11', 'raw-sha1,oracle'
              next unless h['hash'].starts_with? "S:#{hash};".upcase
            when 'oracle12c'
              next unless h['hash'].include? ";T:#{hash}"
            else
              next unless h['hash'] == hash
            end
            cred = {'core_id' => h['id'],
                    'username' => h['un'],
                    'password' => password}
            results = process_crack(results, hashes, cred, hash_type, method)
          end
        end
      end
      results
    end

    tbl = Rex::Text::Table.new(
      'Header'  => 'Cracked Hashes',
      'Indent'   => 1,
      'Columns' => ['DB ID', 'Hash Type', 'Username', 'Cracked Password', 'Method']
    )

    # array of hashes in jtr_format in the db, converted to an OR combined regex
    hashes_regex = []

    if datastore['MSSQL']
      hashes_regex << 'mssql'
      hashes_regex << 'mssql05'
      hashes_regex << 'mssql12'
    end
    if datastore['MYSQL']
      hashes_regex << 'mysql'
      hashes_regex << 'mysql-sha1'
    end
    if datastore['ORACLE']
      # dynamic_1506 is oracle 11/12's H field, MD5.

      # hashcat requires a format we dont have all the data for
      # in the current dumper, so this is disabled in module and lib
      if action.name == 'john'
        hashes_regex << 'oracle'
        hashes_regex << 'dynamic_1506'
      end
      hashes_regex << 'raw-sha1,oracle'
      hashes_regex << 'oracle11'
      hashes_regex << 'oracle12c'
    end
    if datastore['POSTGRES']
      hashes_regex << 'dynamic_1034'
    end

    # check we actually have an action to perform
    fail_with(Failure::BadConfig, 'Please enable at least one database type to crack') if hashes_regex.empty?

    # array of arrays for cracked passwords.
    # Inner array format: db_id, hash_type, username, password, method_of_crack
    results = []

    cracker = new_password_cracker
    cracker.cracker = action.name

    cracker_version = cracker.cracker_version
    if action.name == 'john' and not cracker_version.include?'jumbo'
      fail_with(Failure::BadConfig, 'John the Ripper JUMBO patch version required.  See https://github.com/magnumripper/JohnTheRipper')
    end
    print_good("#{action.name} Version Detected: #{cracker_version}")

    # create the hash file first, so if there aren't any hashes we can quit early
    # hashes is a reference list used by hashcat only
    cracker.hash_path, hashes = hash_file(hashes_regex)

    # generate our wordlist and close the file handle.
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"

    cleanup_files = [cracker.hash_path, wordlist.path]

    hashes_regex.each do |format|
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = format
      if action.name == 'john'
        cracker_instance.fork = datastore['FORK']
      end

      # first check if anything has already been cracked so we don't report it incorrectly
      print_status "Checking #{format} hashes already cracked..."
      results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Already Cracked/POT', cracker_instance)
      vprint_good(print_results(tbl, results))

      if action.name == 'john'
        print_status "Cracking #{format} hashes in single mode..."
        cracker_instance.mode_single(wordlist.path)
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Single', cracker_instance)
        vprint_good(print_results(tbl, results))

        print_status "Cracking #{format} hashes in normal mode"
        cracker_instance.mode_normal
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Normal', cracker_instance)
        vprint_good(print_results(tbl, results))
      end

      print_status "Cracking #{format} hashes in wordlist mode..."
      if action.name == 'john'
        # Turn on KoreLogic rules if the user asked for it
        if datastore['KORELOGIC']
          cracker_instance.rules = 'KoreLogicRules'
          print_status "Applying KoreLogic ruleset..."
        end
      end
      show_command cracker_instance
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Wordlist', cracker_instance)
      vprint_good(print_results(tbl, results))

      if datastore['INCREMENTAL']
        print_status "Cracking #{format} hashes in incremental mode..."
        cracker_instance.mode_incremental
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Incremental', cracker_instance)
        vprint_good(print_results(tbl, results))
      end

      if datastore['WORDLIST']
        print_status "Cracking #{format} hashes in wordlist mode..."
        cracker_instance.mode_wordlist(wordlist.path)
        # Turn on KoreLogic rules if the user asked for it
        if action.name == 'john' && datastore['KORELOGIC']
          cracker_instance.rules = 'KoreLogicRules'
          print_status "Applying KoreLogic ruleset..."
        end
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end

        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Wordlist', cracker_instance)
        vprint_good(print_results(tbl, results))
      end

      #give a final print of results
      print_good(print_results(tbl, results))
    end
    if datastore['DeleteTempFiles']
      cleanup_files.each do |f|
        File.delete(f)
      end
    end
  end

  def hash_file(hashes_regex)
    hashes = []
    wrote_hash = false
    hashlist = Rex::Quickfile.new("hashes_tmp")
    # Convert names from JtR to db
    hashes_regex = hashes_regex.join('|')
    hashes_regex = hashes_regex.gsub('oracle', 'des|oracle')\
              .gsub('dynamic_1506', 'raw-sha1|oracle11|oracle12c|dynamic_1506')\
              .gsub('oracle11', 'raw-sha1|oracle11')\
              .gsub('dynamic_1034', 'postgres|raw-md5')
    regex = Regexp.new hashes_regex
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      next unless core.private.jtr_format =~ regex
      # only add hashes which havne't been cracked
      next unless already_cracked_pass(core.private.data).nil?
      if action.name == 'john'
        hashlist.puts hash_to_jtr(core)
      elsif action.name == 'hashcat'
        # hashcat hash files dont include the ID to reference back to so we build an array to reference
        hashes << {'hash' => core.private.data, 'un' => core.public.username, 'id' => core.id}
        hashlist.puts hash_to_hashcat(core)
      end
      wrote_hash = true
    end
    if datastore['POSTGRES']
      framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::PostgresMD5').each do |core|
        next unless core.private.jtr_format =~ regex
        # only add hashes which havne't been cracked
        next unless already_cracked_pass(core.private.data).nil?
        if action.name == 'john'
          # hashcat hash files dont include the ID to reference back to so we build an array to reference
          # however, for postgres, john doesn't take an id either
          hashes << {'hash' => hash_to_jtr(core), 'un' => core.public.username, 'id' => core.id}
          hashlist.puts hash_to_jtr(core)
        elsif action.name == 'hashcat'
          # hashcat hash files dont include the ID to reference back to so we build an array to reference
          hashes << {'hash' => core.private.data, 'un' => core.public.username, 'id' => core.id}
          hashlist.puts hash_to_hashcat(core)
        end
        wrote_hash = true
      end
    end
    hashlist.close
    unless wrote_hash # check if we wrote anything and bail early if we didn't
      hashlist.delete
      fail_with Failure::NotFound, 'No applicable hashes in database to crack'
    end
    print_status "Hashes Written out to #{hashlist.path}"
    return hashlist.path, hashes
  end
end
