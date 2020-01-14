##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/password_cracker'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker

  def initialize
    super(
      'Name'            => 'Password Cracker: Mobile',
      'Description'     => %Q{
          This module uses Hashcat to identify weak passwords that have been
        acquired from Android systems.  These utilize MD5 or SHA1 hashing.
        Android (Samsung) SHA1 is format 5800 in Hashcat.  Android
        (non-Samsung) SHA1 is format 110 in Hashcat.  Android MD5 is format 10.
        JTR does not support Android hashes at the time of writing.
      },
      'Author'          =>
        [
          'h00die'
        ] ,
      'License'         => MSF_LICENSE,  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
      'Actions'         =>
        [
          ['hashcat', {'Description' => 'Use Hashcat'}],
        ],
      'DefaultAction' => 'hashcat',
    )

    register_options(
      [
        OptBool.new('SAMSUNG',[false, 'Include Samsung SHA1 hashes', true]),
        OptBool.new('SHA1',[false, 'Include Android-SHA1 hashes', true]),
        OptBool.new('MD5',[false, 'Include Android-MD5 hashes', true]),
        OptBool.new('INCREMENTAL',[false, 'Run in incremental mode', true]),
        OptBool.new('WORDLIST',[false, 'Run in wordlist mode', true])
      ]
    )
  end

  def show_command(cracker_instance)
    return unless datastore['ShowCommand']
    if action.name == 'john' # leaving this code here figuring jtr will eventually come around, but its an unused code block
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

    def check_results(passwords, results, hash_type, hashes, method)
      passwords.each do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        if action.name == 'john'
          next unless fields.count >=3
          cred = {}
          cred['username'] = fields.shift
          cred['core_id']  = fields.pop
          4.times { fields.pop } # Get rid of extra :
          cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
          results = process_crack(results, hashes, cred, hash_type, method)
        elsif action.name == 'hashcat'
          next unless fields.count >= 2
          hash = "#{fields.shift}:#{fields.shift}" #grab hash and salt
          password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them
          next if hash.include?("Hashfile '") && hash.include?("' on line ") # skip error lines
          hashes.each do |h|
            next unless h['hash'].downcase == hash.downcase
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
    hashes_regex << 'android-sha1' if datastore['SHA1']
    hashes_regex << 'android-samsung-sha1' if datastore['SAMSUNG']
    hashes_regex << 'android-md5' if datastore['MD5']
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
      results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Already Cracked/POT')
      vprint_good(print_results(tbl, results))

      if action.name == 'john'
        print_status "Cracking #{format} hashes in single mode..."
        cracker_instance.mode_single(wordlist.path)
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Single')
        vprint_good(print_results(tbl, results))

        print_status "Cracking #{format} hashes in normal mode"
        cracker_instance.mode_normal
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Normal')
        vprint_good(print_results(tbl, results))
      end

      if action.name == 'hashcat'
        print_status "Cracking #{format} hashes in pin mode..."
        cracker_instance.mode_pin
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Pin')
        vprint_good(print_results(tbl, results))
      end

      if datastore['INCREMENTAL']
        print_status "Cracking #{format} hashes in incremental mode..."
        cracker_instance.mode_incremental
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Incremental')
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

        results = check_results(cracker_instance.each_cracked_password, results, format, hashes, 'Wordlist')
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
    # descrypt is what JtR calls it, des is what we save it in the db as
    hashes_regex = hashes_regex.join('|')
    regex = Regexp.new hashes_regex
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      next unless core.private.jtr_format =~ regex
      # only add hashes which haven't been cracked
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
    hashlist.close
    unless wrote_hash # check if we wrote anything and bail early if we didn't
      hashlist.delete
      fail_with Failure::NotFound, 'No applicable hashes in database to crack'
    end
    print_status "Hashes Written out to #{hashlist.path}"
    return hashlist.path, hashes
  end
end
