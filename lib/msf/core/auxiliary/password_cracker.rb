# -*- coding: binary -*-
require 'open3'
require 'fileutils'
require 'rex/proto/ntlm/crypt'
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
        OptPath.new('CONFIG',               [false, 'The path to a John config file to use instead of the default']),
        OptPath.new('CUSTOM_WORDLIST',      [false, 'The path to an optional custom wordlist']),
        OptInt.new('ITERATION_TIMEOUT',     [false, 'The max-run-time for each iteration of cracking']),
        OptPath.new('CRACKER_PATH',         [false, 'The absolute path to the cracker executable']),
        OptInt.new('FORK',                  [false, 'Forks for John the Ripper to use',1]),
        OptBool.new('KORELOGIC',            [false, 'Apply the KoreLogic rules to John the Ripper Wordlist Mode(slower)', false]),
        OptBool.new('MUTATE',               [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
        OptPath.new('POT',                  [false, 'The path to a John POT file to use instead of the default']),
        OptBool.new('USE_CREDS',            [false, 'Use existing credential data saved in the database', true]),
        OptBool.new('USE_DB_INFO',          [false, 'Use looted database schema info to seed the wordlist', true]),
        OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
        OptBool.new('USE_HOSTNAMES',        [false, 'Seed the wordlist with hostnames from the workspace', true]),
        OptBool.new('USE_ROOT_WORDS',       [false, 'Use the Common Root Words Wordlist', true])
      ], Msf::Auxiliary::PasswordCracker
    )

    register_advanced_options(
      [
        OptBool.new('DeleteTempFiles',    [false, 'Delete temporary wordlist and hash files', true]),
        OptBool.new('OptimizeKernel',     [false, 'Utilize Optimized Kernels in Hashcat', true]),
        OptBool.new('ShowCommand',        [false, 'Print the cracker command being used', true]),
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
    pwd  = pwd.upcase
    hash = hash.upcase
    Rex::Text.permute_case(pwd).each do |str|
      if hash == Rex::Proto::NTLM::Crypt.ntlm_hash(str).unpack("H*")[0].upcase
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
  def new_password_cracker
    return nil unless framework.db.active
    Metasploit::Framework::PasswordCracker::Cracker.new(
        config: datastore['CONFIG'],
        cracker_path: datastore['CRACKER_PATH'],
        max_runtime: datastore['ITERATION_TIMEOUT'],
        pot: datastore['POT'],
        optimize: datastore['OptimizeKernel'],
        wordlist: datastore['CUSTOM_WORDLIST']
    )
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

  def already_cracked_pass(hash)
    framework.db.creds({:pass => hash}).each do |test_cred|
      test_cred.public.cores.each do |core|
        if core.origin_type == "Metasploit::Credential::Origin::CrackedPassword"
          return core.private.data
        end
      end
    end
    nil
  end

end
end
