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
        OptInt.new('ITERATION_TIMOUT',      [false, 'The max-run-time for each iteration of cracking']),
        OptPath.new('JOHN_PATH',            [false, 'The absolute path to the John the Ripper executable']),
        OptBool.new('MUTATE',               [false, 'Apply common mutations to the Wordlist (SLOW)', false]),
        OptPath.new('POT',                  [false, 'The path to a John POT file to use instead of the default']),
        OptBool.new('USE_CREDS',            [false, 'Use existing credential data saved in the database', true]),
        OptBool.new('USE_DB_INFO',          [false, 'Use looted database schema info to seed the wordlist', true]),
        OptBool.new('USE_DEFAULT_WORDLIST', [false, 'Use the default metasploit wordlist', true]),
        OptBool.new['USE_HOSTNAMES',        [false, 'Seed the wordlist with hostnames from the workspace', true]],
        OptBool.new('USE_ROOT_WORDS',       [false, 'Use the Common Root Words Wordlist', true])
      ], Msf::Auxiliary::JohnTheRipper
    )

  end

  # This method instantiates a {Metasploit::Framework::JtR::Wordlist}, writes the data
  # out to a file and returns the {rex::quickfile} object.
  #
  # @return [nilClass] if there is no active framework db connection
  # @return [Rex::Quickfile] if it successfully wrote the wordlist to a file
  def wordlist_file
    return nil unless framework.db.active?
    wordlist = Metasploit::Framework::JtR::Wordlist.new(
        custom_wordlist: datastore['CUSTOM_WORDLIST'],
        mutate: datastore['MUTATE'],
        pot: datastore['POT'],
        use_creds: datastore['USE_CREDS'],
        use_db_info: datastore['USE_DB_INFO'],
        use_default_wordlist: datastore['USE_DEFAULT_WORDLIST'],
        use_hostnames: datastore['USE_HOSTNAMES'],
        use_common_root: datastore['USE_ROOT_WORDS'],
        workspace: myworkspace
    )
    wordlist.to_file
  end

  def john_cracker
    return nil unless framework.db.active?

  end

  def john_unshadow(passwd_file,shadow_file)

    retval=""

    john_command = john_binary_path

    if john_command.nil?
      print_error("John the Ripper executable not found")
      return nil
    end

    if File.exists?(passwd_file)
      unless File.readable?(passwd_file)
        print_error("We do not have permission to read #{passwd_file}")
        return nil
      end
    else
      print_error("File does not exist: #{passwd_file}")
      return nil
    end

    if File.exists?(shadow_file)
      unless File.readable?(shadow_file)
        print_error("We do not have permission to read #{shadow_file}")
        return nil
      end
    else
      print_error("File does not exist: #{shadow_file}")
      return nil
    end


    cmd = [ john_command.gsub(/john$/, "unshadow"), passwd_file , shadow_file ]

    if RUBY_VERSION =~ /^1\.8\./
      cmd = cmd.join(" ")
    end
    ::IO.popen(cmd, "rb") do |fd|
      fd.each_line do |line|
        retval << line
      end
    end
    return retval
  end

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


end
end
