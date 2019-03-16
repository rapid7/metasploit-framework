# -*- coding: binary -*-
require 'open3'
require 'fileutils'
require 'rex/proto/ntlm/crypt'
require 'metasploit/framework/jtr/cracker'
require 'metasploit/framework/jtr/wordlist'


module Msf

###
#
# This module provides methods for working with John the Ripper
#
###
module Auxiliary::JohnTheRipper
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
        OptPath.new('JOHN_PATH',            [false, 'The absolute path to the John the Ripper executable']),
        OptBool.new('KORELOGIC',            [false, 'Apply the KoreLogic rules to Wordlist Mode(slower)', false]),
        OptBool.new('MUTATE',               [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
        OptPath.new('POT',                  [false, 'The path to a John POT file to use instead of the default']),
        OptBool.new('USE_CREDS',            [false, 'Use existing credential data saved in the database', true]),
        OptBool.new('USE_DB_INFO',          [false, 'Use looted database schema info to seed the wordlist', true]),
        OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
        OptBool.new('USE_HOSTNAMES',        [false, 'Seed the wordlist with hostnames from the workspace', true]),
        OptBool.new('USE_ROOT_WORDS',       [false, 'Use the Common Root Words Wordlist', true])
      ], Msf::Auxiliary::JohnTheRipper
    )

    register_advanced_options(
      [
        OptBool.new('DELETE_TEMP_FILES',    [false, 'Delete temporary wordlist and hash files', true])
      ], Msf::Auxiliary::JohnTheRipper
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


  # This method creates a new {Metasploit::Framework::JtR::Cracker} and populates
  # some of the attributes based on the module datastore options.
  #
  # @return [nilClass] if there is no active framework db connection
  # @return [Metasploit::Framework::JtR::Cracker] if it successfully creates a JtR Cracker object
  def new_john_cracker
    return nil unless framework.db.active
    Metasploit::Framework::JtR::Cracker.new(
        config: datastore['CONFIG'],
        john_path: datastore['JOHN_PATH'],
        max_runtime: datastore['ITERATION_TIMEOUT'],
        pot: datastore['POT'],
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
    wordlist = Metasploit::Framework::JtR::Wordlist.new(
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

  # This method takes a {framework.db.cred}, and normalizes it
  # to the string format JTR is expecting.
  #
  # @param [credClass] a credential from framework.db
  # @return [String] the hash in jtr format or nil on no mach
  def hash_to_jtr(cred)
    case cred.private.type
    when 'Metasploit::Credential::NTLMHash'
      return "#{cred.public.username}:#{cred.id}:#{cred.private.data}:::#{cred.id}"
    when 'Metasploit::Credential::PostgresMD5'
      if cred.private.jtr_format =~ /postgres|raw-md5/
        # john --list=subformats | grep 'PostgreSQL MD5'
        #UserFormat = dynamic_1034  type = dynamic_1034: md5($p.$u) (PostgreSQL MD5)
        hash_string = cred.private.data
        hash_string.gsub!(/^md5/, '')
        return "#{cred.public.username}:$dynamic_1034$#{hash_string}"
      end
    when 'Metasploit::Credential::NonreplayableHash'
      case cred.private.jtr_format
        # oracle 11+ password hash descriptions:
        # this password is stored as a long ascii string with several sections
        # https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/changes-in-oracle-database-12c-password-hashes/
        # example:
        # hash = []
        # hash << "S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;"
        # hash << "H:DC9894A01797D91D92ECA1DA66242209;"
        # hash << "T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C"
        # puts hash.join('')
        # S: = 60 characters -> sha1(password + salt (10 bytes))
        #         40 char sha1, 20 char salt
        #         hash is 8F2D65FB5547B71C8DA3760F10960428CD307B1C
        #         salt is 6271691FC55C1F56554A
        # H: = 32 characters
        #         legacy MD5
        # T: = 160 characters
        #         PBKDF2-based SHA512 hash specific to 12C (12.1.0.2+)
      when /raw-sha1|oracle11/ # oracle 11
        if cred.private.data =~ /S:([\dA-F]{60})/ # oracle 11
          return "#{cred.public.username}:#{$1}:#{cred.id}:"
        end
      when /oracle12c/
        if cred.private.data =~ /T:([\dA-F]{160})/ # oracle 12c
          return "#{cred.public.username}:$oracle12c$#{$1.downcase}:#{cred.id}:"
        end
      when /dynamic_1506/
        if cred.private.data =~ /H:([\dA-F]{32})/ # oracle 11
          return "#{cred.public.username.upcase}:$dynamic_1506$#{$1}:#{cred.id}:"
        end
      when /oracle/ # oracle
        if cred.private.jtr_format.start_with?('des') # 'des,oracle', not oracle11/12c
          return "#{cred.public.username}:O$#{cred.public.username}##{cred.private.data}:#{cred.id}:"
        end
      when /md5|des|bsdi|crypt|bf/
        # md5(crypt), des(crypt), b(crypt)
        return "#{cred.public.username}:#{cred.private.data}:::::#{cred.id}:"
      else
        # /mysql|mysql-sha1/
        # /mssql|mssql05|mssql12/
        # /des(crypt)/
        return "#{cred.public.username}:#{cred.private.data}:#{cred.id}:"
      end
    end
    nil
  end
end
end
