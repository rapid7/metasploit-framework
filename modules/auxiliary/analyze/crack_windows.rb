##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/analyze/jtr_windows_fast'

  def initialize
    super(
      'Name' => 'Password Cracker: Windows',
      'Description' => %(
          This module uses John the Ripper or Hashcat to identify weak passwords that have been
        acquired from Windows systems.
        LANMAN is format 3000 in hashcat.
        NTLM is format 1000 in hashcat.
        MSCASH is format 1100 in hashcat.
        MSCASH2 is format 2100 in hashcat.
        NetNTLM is format 5500 in hashcat.
        NetNTLMv2 is format 5600 in hashcat.
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
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptBool.new('NTLM', [false, 'Crack NTLM hashes', true]),
        OptBool.new('LANMAN', [false, 'Crack LANMAN hashes', true]),
        OptBool.new('MSCASH', [false, 'Crack M$ CASH hashes (1 and 2)', true]),
        OptBool.new('NETNTLM', [false, 'Crack NetNTLM', true]),
        OptBool.new('NETNTLMV2', [false, 'Crack NetNTLMv2', true]),
        OptBool.new('INCREMENTAL', [false, 'Run in incremental mode', true]),
        OptBool.new('WORDLIST', [false, 'Run in wordlist mode', true]),
        OptBool.new('NORMAL', [false, 'Run in normal mode (John the Ripper only)', true])
      ]
    )
  end

  def half_lm_regex
    # ^\?{7} is ??????? which is JTR format, so password would be ???????D
    # ^[notfound] is hashcat format, so password would be [notfound]D
    /^[?{7}|\[notfound\]]/
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

  # we have to overload the process_cracker_results from password_cracker.rb since LANMAN
  # is a special case where we may need to do some combining
  def process_cracker_results(results, cred)
    return results if cred['core_id'].nil? # make sure we have good data

    # make sure we dont add the same one again
    if results.select { |r| r.first == cred['core_id'] }.empty?
      results << [cred['core_id'], cred['hash_type'], cred['username'], cred['password'], cred['method']]
    end

    # however, a special case for LANMAN where it may come back as ???????D (jtr) or [notfound]D (hashcat)
    # we want to overwrite the one that was there *if* we have something better.
    results.map! do |r|
      if r.first == cred['core_id'] &&
         r[3] =~ half_lm_regex
        [cred['core_id'], cred['hash_type'], cred['username'], cred['password'], cred['method']]
      else
        r
      end
    end

    create_cracked_credential(username: cred['username'], password: cred['password'], core_id: cred['core_id'])
    results
  end

  def check_results(passwords, results, hash_type, method)
    passwords.each do |password_line|
      password_line.chomp!
      next if password_line.blank?

      fields = password_line.split(':')
      cred = { 'hash_type' => hash_type, 'method' => method }
      if action.name == 'john'
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count > 2

        cred['username'] = fields.shift
        cred['core_id'] = fields.pop
        case hash_type
        when 'mscash', 'mscash2', 'netntlm', 'netntlmv2'
          cred['password'] = fields.shift
        when 'lm', 'nt'
          # If we don't have an expected minimum number of fields, this is probably not a NTLM hash
          next unless fields.count >= 6

          2.times { fields.pop } # Get rid of extra :
          nt_hash = fields.pop
          fields.pop
          fields.pop
          password = fields.join(':') # Anything left must be the password. This accounts for passwords with semi-colons in it
          if hash_type == 'lm' && password.blank?
            if nt_hash == Metasploit::Credential::NTLMHash::BLANK_NT_HASH
              password = ''
            else
              next
            end
          end

          # password can be nil if the hash is broken (i.e., the NT and
          # LM sides don't actually match) or if john was only able to
          # crack one half of the LM hash. In the latter case, we'll
          # have a line like:
          #  username:???????WORD:...:...:::
          cred['password'] = john_lm_upper_to_ntlm(password, nt_hash)
        end
        next if cred['password'].nil?
      elsif action.name == 'hashcat'
        next unless fields.count >= 2

        cred['core_id'] = fields.shift

        if ['netntlm', 'netntlmv2'].include? hash_type
          # we could grab the username here, but no need since we grab it later based on core_id, which is safer
          6.times { fields.shift } # Get rid of a bunch of extra fields
        else
          cred['hash'] = fields.shift
        end

        fields.pop if hash_type == 'mscash' # Get rid of username

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

  def run
    tbl = cracker_results_table

    # array of hashes in jtr_format in the db, converted to an OR combined regex
    hash_types_to_crack = []
    hash_types_to_crack << 'lm' if datastore['LANMAN']
    hash_types_to_crack << 'nt' if datastore['NTLM']
    hash_types_to_crack << 'mscash' if datastore['MSCASH']
    hash_types_to_crack << 'mscash2' if datastore['MSCASH']
    hash_types_to_crack << 'netntlm' if datastore['NETNTLM']
    hash_types_to_crack << 'netntlmv2' if datastore['NETNTLMV2']

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

        if datastore['NORMAL']
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
