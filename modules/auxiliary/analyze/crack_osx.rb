##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker

  def initialize
    super(
      'Name' => 'Password Cracker: OSX',
      'Description' => %(
          This module uses John the Ripper or Hashcat to identify weak passwords that have been
        acquired from OSX systems. The module will only crack xsha from OSX 10.4-10.6, xsha512
        from 10.7, and PBKDF2 from OSX 10.8+.
        XSHA is 122 in hashcat.
        XSHA512 is 1722 in hashcat.
        PBKDF2 (PBKDF2-HMAC-SHA512) is 7100 in hashcat.
      ),
      'Author' => [
        'h00die' # hashcat integration
      ],
      'License' => MSF_LICENSE, # JtR itself is GPLv2, but this wrapper is MSF (BSD)
      'Actions' => [
        ['john', { 'Description' => 'Use John the Ripper' }],
        ['hashcat', { 'Description' => 'Use Hashcat' }],
      ],
      'DefaultAction' => 'john',
    )

    register_options(
      [
        OptBool.new('XSHA', [false, 'Include XSHA hashes from 10.4-10.6', true]),
        OptBool.new('XSHA512', [false, 'Include XSHA512 hashes from 10.7', true]),
        OptBool.new('PBKDF2', [false, 'Include PBKDF2-HMAC-SHA512 hashes from 10.8+', true]),
        OptBool.new('INCREMENTAL', [false, 'Run in incremental mode', true]),
        OptBool.new('WORDLIST', [false, 'Run in wordlist mode', true])
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

  def run
    def check_results(passwords, results, hash_type, method)
      passwords.each do |password_line|
        password_line.chomp!
        next if password_line.blank?

        fields = password_line.split(':')
        cred = { 'hash_type' => hash_type, 'method' => method }
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        if action.name == 'john'
          next unless fields.count >= 3

          cred['username'] = fields.shift
          cred['core_id'] = fields.pop
          unless hash_type == 'PBKDF2-HMAC-SHA512'
            4.times { fields.pop } # Get rid of extra :
          end
          cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
        elsif action.name == 'hashcat'
          next unless fields.count >= 3

          cred['core_id'] = fields.shift
          cred['hash'] = fields.shift
          cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
          next if cred['core_id'].include?("Hashfile '") && cred['core_id'].include?("' on line ") # skip error lines

          # we don't have the username since we overloaded it with the core_id (since its a better fit for us)
          # so we can now just go grab the username from the DB
          cred['username'] = framework.db.creds(workspace: myworkspace, id: cred['core_id'])[0].public.username
        end
        results = process_cracker_results(results, cred)
      end
      results
    end

    tbl = tbl = cracker_results_table

    # array of hashes in jtr_format in the db, converted to an OR combined regex
    hash_types_to_crack = []
    hash_types_to_crack << 'xsha' if datastore['XSHA']
    hash_types_to_crack << 'xsha512' if datastore['XSHA512']
    hash_types_to_crack << 'PBKDF2-HMAC-SHA512' if datastore['PBKDF2']
    jobs_to_do = []

    # build our job list
    hash_types_to_crack.each do |hash_type|
      job = hash_job(hash_type, action.name)
      if job.nil?
        print_status("No #{hash_type} found to crack")
      else
        jobs_to_do << job
      end
    end

    # bail early of no jobs to do
    if jobs_to_do.empty?
      print_good("No uncracked password hashes found for: #{hash_types_to_crack.join(', ')}")
      return
    end

    # array of arrays for cracked passwords.
    # Inner array format: db_id, hash_type, username, password, method_of_crack
    results = []

    cracker = new_password_cracker(action.name)

    # generate our wordlist and close the file handle.
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"

    cleanup_files = [wordlist.path]

    jobs_to_do.each do |job|
      format = job['type']
      hash_file = Rex::Quickfile.new("hashes_#{job['type']}_")
      hash_file.puts job['formatted_hashlist']
      hash_file.close
      cracker.hash_path = hash_file.path
      cleanup_files << hash_file.path
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = format
      if action.name == 'john'
        cracker_instance.fork = datastore['FORK']
      end

      # first check if anything has already been cracked so we don't report it incorrectly
      print_status "Checking #{format} hashes already cracked..."
      results = check_results(cracker_instance.each_cracked_password, results, format, 'Already Cracked/POT')
      vprint_good(append_results(tbl, results)) unless results.empty?

      if action.name == 'john'
        print_status "Cracking #{format} hashes in single mode..."
        cracker_instance.mode_single(wordlist.path)
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, 'Single')
        vprint_good(append_results(tbl, results)) unless results.empty?
        job['cred_ids_left_to_crack'] = job['cred_ids_left_to_crack'] - results.map { |i| i[0].to_i } # remove cracked hashes from the hash list
        next if job['cred_ids_left_to_crack'].empty?

        print_status "Cracking #{format} hashes in normal mode..."
        cracker_instance.mode_normal
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, 'Normal')
        vprint_good(append_results(tbl, results)) unless results.empty?
        job['cred_ids_left_to_crack'] = job['cred_ids_left_to_crack'] - results.map { |i| i[0].to_i } # remove cracked hashes from the hash list
        next if job['cred_ids_left_to_crack'].empty?
      end

      if datastore['INCREMENTAL']
        print_status "Cracking #{format} hashes in incremental mode..."
        cracker_instance.mode_incremental
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end
        results = check_results(cracker_instance.each_cracked_password, results, format, 'Incremental')
        vprint_good(append_results(tbl, results)) unless results.empty?
        job['cred_ids_left_to_crack'] = job['cred_ids_left_to_crack'] - results.map { |i| i[0].to_i } # remove cracked hashes from the hash list
        next if job['cred_ids_left_to_crack'].empty?
      end

      if datastore['WORDLIST']
        print_status "Cracking #{format} hashes in wordlist mode..."
        cracker_instance.mode_wordlist(wordlist.path)
        # Turn on KoreLogic rules if the user asked for it
        if action.name == 'john' && datastore['KORELOGIC']
          cracker_instance.rules = 'KoreLogicRules'
          print_status 'Applying KoreLogic ruleset...'
        end
        show_command cracker_instance
        cracker_instance.crack do |line|
          vprint_status line.chomp
        end

        results = check_results(cracker_instance.each_cracked_password, results, format, 'Wordlist')
        vprint_good(append_results(tbl, results)) unless results.empty?
        job['cred_ids_left_to_crack'] = job['cred_ids_left_to_crack'] - results.map { |i| i[0].to_i } # remove cracked hashes from the hash list
        next if job['cred_ids_left_to_crack'].empty?
      end

      # give a final print of results
      print_good(append_results(tbl, results))
    end
    if datastore['DeleteTempFiles']
      cleanup_files.each do |f|
        File.delete(f)
      end
    end
  end
end
