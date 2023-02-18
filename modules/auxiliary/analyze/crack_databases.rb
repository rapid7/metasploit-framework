##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/analyze/jtr_mssql_fast'
  moved_from 'auxiliary/analyze/jtr_mysql_fast'
  moved_from 'auxiliary/analyze/jtr_oracle_fast'
  moved_from 'auxiliary/analyze/jtr_postgres_fast'

  def initialize
    super(
      'Name' => 'Password Cracker: Databases',
      'Description' => %(
          This module uses John the Ripper or Hashcat to identify weak passwords that have been
        acquired from the mssql_hashdump, mysql_hashdump, postgres_hashdump, or oracle_hashdump modules.
        Passwords that have been successfully cracked are then saved as proper credentials.
        Due to the complexity of some of the hash types, they can be very slow.  Setting the
        ITERATION_TIMEOUT is highly recommended.
        MSSQL is 131, 132, and 1731 in hashcat.
        MYSQL is 200, and 300 in hashcat.
        ORACLE is 112, and 12300 in hashcat.
        POSTGRES is 12 in hashcat.
      ),
      'Author' => [
        'theLightCosine',
        'hdm',
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
        OptBool.new('MSSQL', [false, 'Include MSSQL hashes', true]),
        OptBool.new('MYSQL', [false, 'Include MySQL hashes', true]),
        OptBool.new('ORACLE', [false, 'Include Oracle hashes', true]),
        OptBool.new('POSTGRES', [false, 'Include Postgres hashes', true]),
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

        if action.name == 'john'
          next unless fields.count >= 3

          cred['username'] = fields.shift
          cred['core_id'] = fields.pop
          cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
        elsif action.name == 'hashcat'
          next unless fields.count >= 2

          case hash_type
          when 'dynamic_1034'
            # for postgres we get 4 fields, id:hash:un:pass.
            cred['core_id'] = fields.shift
            cred['hash'] = fields.shift
            cred['username'] = fields.shift
            cred['password'] = fields.join(':')
          when 'oracle11', 'raw-sha1,oracle'
            cred['core_id'] = fields.shift
            cred['hash'] = "#{fields.shift}#{fields.shift}" # we pull the first two fields, hash and salt
            cred['password'] = fields.join(':')
          else
            cred['core_id'] = fields.shift
            cred['hash'] = fields.shift
            cred['password'] = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
          end

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

    if datastore['MSSQL']
      hash_types_to_crack << 'mssql'
      hash_types_to_crack << 'mssql05'
      hash_types_to_crack << 'mssql12'
    end
    if datastore['MYSQL']
      hash_types_to_crack << 'mysql'
      hash_types_to_crack << 'mysql-sha1'
    end
    if datastore['ORACLE']
      # dynamic_1506 is oracle 11/12's H field, MD5.

      # hashcat requires a format we dont have all the data for
      # in the current dumper, so this is disabled in module and lib
      if action.name == 'john'
        hash_types_to_crack << 'oracle'
        hash_types_to_crack << 'dynamic_1506'
      end
      hash_types_to_crack << 'oracle11'
      hash_types_to_crack << 'oracle12c'
    end
    if datastore['POSTGRES']
      hash_types_to_crack << 'dynamic_1034'
    end

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
      job['cred_ids_left_to_crack'] = job['cred_ids_left_to_crack'] - results.map { |i| i[0].to_i } # remove cracked hashes from the hash list
      next if job['cred_ids_left_to_crack'].empty?

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
