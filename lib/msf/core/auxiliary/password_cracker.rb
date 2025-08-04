# -*- coding: binary -*-

require 'open3'
require 'fileutils'
require 'metasploit/framework/password_crackers/cracker'
require 'metasploit/framework/password_crackers/wordlist'
require 'metasploit/framework/password_crackers/jtr/formatter'
require 'metasploit/framework/password_crackers/hashcat/formatter'

module Msf
  ###
  #
  # This module provides methods for working with a Password Cracker
  #
  ###
  module Auxiliary::PasswordCracker
    include Msf::Auxiliary::Report

    #
    # Initializes an instance of an auxiliary module that calls out to John the Ripper (jtr)
    #

    def initialize(info = {})
      super

      register_options(
        [
          OptPath.new('CONFIG', [false, 'The path to a John config file to use instead of the default']),
          OptPath.new('CUSTOM_WORDLIST', [false, 'The path to an optional custom wordlist']),
          OptInt.new('ITERATION_TIMEOUT', [false, 'The max-run-time for each iteration of cracking']),
          OptPath.new('CRACKER_PATH', [false, 'The absolute path to the cracker executable']),
          OptInt.new('FORK', [false, 'Forks for John the Ripper to use', 1]),
          OptBool.new('KORELOGIC', [false, 'Apply the KoreLogic rules to John the Ripper Wordlist Mode(slower)', false]),
          OptBool.new('MUTATE', [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
          OptPath.new('POT', [false, 'The path to a John POT file to use instead of the default']),
          OptBool.new('USE_CREDS', [false, 'Use existing credential data saved in the database', true]),
          OptBool.new('USE_DB_INFO', [false, 'Use looted database schema info to seed the wordlist', true]),
          OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
          OptBool.new('USE_HOSTNAMES', [false, 'Seed the wordlist with hostnames from the workspace', true]),
          OptBool.new('USE_ROOT_WORDS', [false, 'Use the Common Root Words Wordlist', true])
        ], Msf::Auxiliary::PasswordCracker
      )

      register_advanced_options(
        [
          OptBool.new('DeleteTempFiles', [false, 'Delete temporary wordlist and hash files', true]),
          OptBool.new('OptimizeKernel', [false, 'Utilize Optimized Kernels in Hashcat', true]),
          OptBool.new('ShowCommand', [false, 'Print the cracker command being used', true]),
        ], Msf::Auxiliary::PasswordCracker
      )
    end

    # @param pwd [String] Password recovered from cracking an LM hash
    # @param hash [String] NTLM hash for this password
    # @return [String] `pwd` converted to the correct case to match the
    #   given NTLM hash
    # @return [nil] if no case matches the NT hash. This can happen when
    #   `pwd` came from a john run that only cracked half of the LM hash
    def john_lm_upper_to_ntlm(pwd, hash)
      pwd = pwd.upcase
      hash = hash.upcase
      Rex::Text.permute_case(pwd).each do |str|
        if hash == Rex::Proto::NTLM::Crypt.ntlm_hash(str).unpack('H*')[0].upcase
          return str
        end
      end
      nil
    end

    # This method creates a new {Metasploit::Framework::PasswordCracker::Cracker} and populates
    # some of the attributes based on the module datastore options.
    #
    # @return [nilClass] if there is no active framework db connection
    # @return [Metasploit::Framework::PasswordCracker::Cracker] if it successfully creates a Password Cracker object
    def new_password_cracker(cracking_application)
      fail_with(Msf::Module::Failure::BadConfig, 'Password cracking is not available without an active database connection.') unless framework.db.active
      cracker = Metasploit::Framework::PasswordCracker::Cracker.new(
        config: datastore['CONFIG'],
        cracker_path: datastore['CRACKER_PATH'],
        max_runtime: datastore['ITERATION_TIMEOUT'],
        pot: datastore['POT'],
        optimize: datastore['OptimizeKernel'],
        wordlist: datastore['CUSTOM_WORDLIST']
      )
      cracker.cracker = cracking_application
      begin
        cracker.binary_path
      rescue Metasploit::Framework::PasswordCracker::PasswordCrackerNotFoundError => e
        fail_with(Msf::Module::Failure::BadConfig, e.message)
      end
      # throw this to a local variable since it causes a shell out to pull the version
      cracker_version = cracker.cracker_version
      if cracker.cracker == 'john' && (cracker_version.nil? || !cracker_version.include?('jumbo'))
        fail_with(Msf::Module::Failure::BadConfig, 'John the Ripper JUMBO patch version required.  See https://github.com/magnumripper/JohnTheRipper')
      end
      print_good("#{cracker.cracker} Version Detected: #{cracker_version}")
      cracker
    end

    # This method instantiates a {Metasploit::Framework::JtR::Wordlist}, writes the data
    # out to a file and returns the {Rex::Quickfile} object.
    #
    # @param max_len [Integer] max length of a word in the wordlist, 0 default for ignored value
    # @return [nilClass] if there is no active framework db connection
    # @return [Rex::Quickfile] if it successfully wrote the wordlist to a file
    def wordlist_file(max_len = 0)
      return nil unless framework.db.active

      wordlist = Metasploit::Framework::PasswordCracker::Wordlist.new(
        custom_wordlist: datastore['CUSTOM_WORDLIST'],
        mutate: datastore['MUTATE'],
        use_creds: datastore['USE_CREDS'],
        use_db_info: datastore['USE_DB_INFO'],
        use_default_wordlist: datastore['USE_DEFAULT_WORDLIST'],
        use_hostnames: datastore['USE_HOSTNAMES'],
        use_common_root: datastore['USE_ROOT_WORDS'],
        workspace: myworkspace
      )
      wordlist.to_file(max_len)
    end

    # This method determines if a given password hash already been cracked in the database
    #
    # @param hash [String] password hash to check against the database
    # @return [Boolean] if the password has been cracked in the db
    def password_cracked?(hash)
      framework.db.creds({ pass: hash }).each do |test_cred|
        test_cred.public.cores.each do |core|
          if core.origin_type == 'Metasploit::Credential::Origin::CrackedPassword'
            return true
          end
        end
      end
      false
    end

    # This method creates a job for the password cracker to do. A job is categorized by the hash type
    # and will include the hash type (type), formatted_hashlist (hashes in the cracker's format),
    # creds (db objects for each hash), and cred_ids_left_to_crack (array of db ids that aren't cracked yet)
    #
    # @param jtr_type [String] hash type we're cracking such as md5, sha1
    # @param cracker [String] the password cracker to use such as 'john' or 'hashcat'
    # @return [Hash] of the data needed to crack as described above
    def hash_job(jtr_type, cracker)
      # create the base data
      job = { 'type' => jtr_type, 'formatted_hashlist' => [], 'creds' => [], 'cred_ids_left_to_crack' => [] }
      job['db_formats'] = Metasploit::Framework::PasswordCracker::JtR::Formatter.jtr_to_db(jtr_type)
      if jtr_type == 'dynamic_1034' # postgres
        creds = framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::PostgresMD5')
      elsif ['lm', 'nt'].include? jtr_type
        creds = framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NTLMHash')
      else
        creds = framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash')
      end
      creds.each do |core|
        jtr_format = core.private.jtr_format

        # Unfortunately NTLMHash always set JtR Format to 'nt,lm' so we have to do a special case here
        # to figure out which it is
        if jtr_format == 'nt,lm'
          jtr_format = core.private.data.start_with?('aad3b435b51404eeaad3b435b51404ee') ? 'nt' : 'lm'
        end

        next unless job['db_formats'].include? jtr_format
        # only add hashes which havne't been cracked
        next if password_cracked?(core.private.data)

        job['creds'] << core
        job['cred_ids_left_to_crack'] << core.id
        if cracker == 'john'
          job['formatted_hashlist'] << Metasploit::Framework::PasswordCracker::JtR::Formatter.hash_to_jtr(core)
        elsif cracker == 'hashcat'
          job['formatted_hashlist'] << Metasploit::Framework::PasswordCracker::Hashcat::Formatter.hash_to_hashcat(core)
        end
      end

      if job['creds'].length > 0
        return job
      end

      nil
    end

    # This method takes a results table, and a newly cracked cred, and adds the cred to the table if
    # it isn't there already.  It also creates the cracked credential in the database.
    #
    # @param results [Hash] Hash of the newly cracked cred information, should have hash_type, method, username
    #   core_id, and password fields.
    # @return [Array] Array of results for printing in a table
    def process_cracker_results(results, cred)
      return results if cred['core_id'].nil? # make sure we have good data

      # make sure we dont add the same one again
      if results.select { |r| r.first == cred['core_id'] }.empty?
        results << [cred['core_id'], cred['hash_type'], cred['username'], cred['password'], cred['method']]
      end

      create_cracked_credential(username: cred['username'], password: cred['password'], core_id: cred['core_id'])
      results
    end

    # This method appends a list of cracked hashes to the list used to generate the printed table
    #
    # @param tbl [Array] Array of all results that have been cracked
    # @param cracked_hashes [Array] Array of results to add to the table
    # @return [String] the table in string format for printing
    def append_results(tbl, cracked_hashes)
      cracked_hashes.each do |row|
        next if tbl.rows.include? row

        tbl << row
      end
      tbl.to_s
    end

    # This method returns a cracker results table
    #
    # @return [Rex::Text::Table] table for printing results
    def cracker_results_table
      Rex::Text::Table.new(
        'Header' => 'Cracked Hashes',
        'Indent' => 1,
        'Columns' => ['DB ID', 'Hash Type', 'Username', 'Cracked Password', 'Method']
      )
    end
  end
end
