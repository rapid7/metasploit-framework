#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script will look up a collection of MD5 hashes (from a file) against the following databases
# via md5cracker.org:
# authsecu, i337.net, md5.my-addr.com, md5.net, md5crack, md5cracker.org, md5decryption.com,
# md5online.net, md5pass, netmd5crack, tmto.
# This msf tool script was originally ported from:
# https://github.com/hasherezade/metasploit_modules/blob/master/md5_lookup.rb
#
# To-do:
# Maybe as a msf plugin one day and grab hashes directly from the workspace.
#
# Authors:
# * hasherezade (http://hasherezade.net, @hasherezade)
# * sinn3r (ported the module as a standalone msf tool)
#

#
# Load our MSF API
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'
require 'rex'
require 'msf/core'
require 'optparse'

#
# Basic prints we can't live without
#

# Prints with [*] that represents the message is a status
#
# @param msg [String] The message to print
# @return [void]
def print_status(msg='')
  $stdout.puts "[*] #{msg}"
end

# Prints with [-] that represents the message is an error
#
# @param msg [String] The message to print
# @return [void]
def print_error(msg='')
  $stdout.puts "[-] #{msg}"
end

module Md5LookupUtility

  # This class manages the disclaimer
  class Disclaimer

    # @!attribute config_file
    #  @return [String] The config file path
    attr_accessor :config_file

    # @!attribute group_name
    #  @return [String] The name of the tool
    attr_accessor :group_name

    def initialize
      self.config_file = Msf::Config.config_file
      self.group_name  = 'MD5Lookup'
    end

    # Prompts a disclaimer. The user will not be able to get out unless they acknowledge.
    #
    # @return [TrueClass] true if acknowledged.
    def ack
      print_status("WARNING: This tool will look up your MD5 hashes by submitting them")
      print_status("in the clear (HTTP) to third party websites. This can expose")
      print_status("sensitive data to unknown and untrusted entities.")

      while true
        $stdout.print "[*] Enter 'Y' to acknowledge: "
          if $stdin.gets =~ /^y|yes$/i
            return true
          end
      end
    end

    # Saves the waiver so the warning won't show again after ack
    #
    # @return [void]
    def save_waiver
      save_setting('waiver', true)
    end

    # Returns true if we don't have to show the warning again
    #
    # @return [Boolean]
    def has_waiver?
      load_setting('waiver') == 'true' ? true : false
    end

    private

    # Saves a setting to Metasploit's config file
    #
    # @param key_name [String] The name of the setting
    # @param value [String] The value of the setting
    # @return [void]
    def save_setting(key_name, value)
      ini = Rex::Parser::Ini.new(self.config_file)
      ini.add_group(self.group_name) if ini[self.group_name].nil?
      ini[self.group_name][key_name] = value
      ini.to_file(self.config_file)
    end

    # Returns the value of a specific setting
    #
    # @param key_name [String] The name of the setting
    # @return [String]
    def load_setting(key_name)
      ini = Rex::Parser::Ini.new(self.config_file)
      group = ini[self.group_name]
      return '' if group.nil?
      group[key_name].to_s
    end

  end

  # This class is basically an auxiliary module without relying on msfconsole
  class Md5Lookup < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient

    # @!attribute rhost
    #  @return [String] Should be md5cracker.org
    attr_accessor :rhost

    # @!attribute rport
    #  @return [Integer] The port number to md5cracker.org
    attr_accessor :rport

    # @!attribute target_uri
    #  @return [String] The URI (API)
    attr_accessor :target_uri

    # @!attribute ssl
    #  @return [FalseClass] False because doesn't look like md5cracker.org supports HTTPS
    attr_accessor :ssl

    def initialize(opts={})
      # The user should not be able to modify these settings, otherwise
      # the we can't guarantee results.
      self.rhost      = 'md5cracker.org'
      self.rport      = 80
      self.target_uri = '/api/api.cracker.php'
      self.ssl        = false

      super(
        'DefaultOptions' =>
          {
            'SSL'   => self.ssl,
            'RHOST' => self.rhost,
            'RPORT' => self.rport
          }
      )
    end

    # Returns the found cracked MD5 hash
    #
    # @param md5_hash [String] The MD5 hash to lookup
    # @param db [String] The specific database to check against
    # @return [String] Found cracked MD5 hash
    def lookup(md5_hash, db)
      res = send_request_cgi({
        'uri'      => self.target_uri,
        'method'   => 'GET',
        'vars_get' => {'database' => db, 'hash' => md5_hash}
      })
      get_json_result(res)
    end

    private

    # Parses the cracked result from a JSON input
    # @param res [Rex::Proto::Http::Response] The Rex HTTP response
    # @return [String] Found cracked MD5 hash
    def get_json_result(res)
      result = ''

      # Hmm, no proper response :-(
      return result unless res && res.code == 200

      begin
        json = JSON.parse(res.body)
        result = json['result'] if json['status']
      rescue JSON::ParserError
        # No json?
      end

      result
    end

  end

  # This class parses the user-supplied options (inputs)
  class OptsConsole

    # The databases supported by md5cracker.org
    # The hash keys (symbols) are used as choices for the user, the hash values are the original
    # database values that md5cracker.org will recognize
    DATABASES =
        {
          :all           => nil, # This is shifted before being passed to Md5Lookup
          :authsecu      => 'authsecu',
          :i337          => 'i337.net',
          :md5_my_addr   => 'md5.my-addr.com',
          :md5_net       => 'md5.net',
          :md5crack      => 'md5crack',
          :md5cracker    => 'md5cracker.org',
          :md5decryption => 'md5decryption.com',
          :md5online     => 'md5online.net',
          :md5pass       => 'md5pass',
          :netmd5crack   => 'netmd5crack',
          :tmto          => 'tmto'
        }

    # The default file path to save the results to
    DEFAULT_OUTFILE = 'md5_results.txt'

    # Returns the normalized user inputs
    #
    # @param args [Array] This should be Ruby's ARGV
    # @raise [OptionParser::MissingArgument] Missing arguments
    # @return [Hash] The normalized options
    def self.parse(args)
      parser, options = get_parsed_options

      # Set the optional datation argument (--database)
      unless options[:databases]
        options[:databases] = get_database_names
      end

      # Set the optional output argument (--out)
      unless options[:outfile]
        options[:outfile] = DEFAULT_OUTFILE
      end

      # Now let's parse it
      # This may raise OptionParser::InvalidOption
      parser.parse!(args)

      # Final checks
      if options.empty?
        raise OptionParser::MissingArgument, 'No options set, try -h for usage'
      elsif options[:input].blank?
        raise OptionParser::MissingArgument, '-i is a required argument'
      end

      options
    end

    private

    # Returns the parsed options from ARGV
    #
    # raise [OptionParser::InvalidOption] Invalid option found
    # @return [OptionParser, Hash] The OptionParser object and an hash containg the options
    def self.get_parsed_options
      options = {}
      parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options]"
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-i', '--input <file>',
          'The file that contains all the MD5 hashes (one line per hash)') do |v|
          if v && !::File.exist?(v)
            raise OptionParser::InvalidOption, "Invalid input file: #{v}"
          end

          options[:input] = v
        end

        opt.on('-d','--databases <names>',
          "(Optional) Select databases: #{get_database_symbols * ", "} (Default=all)") do |v|
          options[:databases] = extract_db_names(v)
        end

        opt.on('-o', '--out <filepath>',
          "(Optional) Save the results to a file (Default=#{DEFAULT_OUTFILE})") do |v|
          options[:outfile] = v
        end

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end
      return parser, options
    end

    # Returns the actual database names based on what the user wants
    #
    # @param list [String] A list of user-supplied database names
    # @return [Array<String>] All the matched database names
    def self.extract_db_names(list)
      new_db_list = []

      list_copy = list.split(',')

      if list_copy.include?('all')
        return get_database_names
      end

      list_copy.each do |item|
        item = item.strip.to_sym
        new_db_list << DATABASES[item] if DATABASES[item]
      end

      new_db_list
    end

    # Returns a list of all of the supported database symbols
    #
    # @return [Array<Symbol>] Database symbols
    def self.get_database_symbols
      DATABASES.keys
    end

    # Returns a list of all the original database values recognized by md5cracker.org
    #
    # @return [Array<String>] Original database values
    def self.get_database_names
      new_db_list = DATABASES.values
      new_db_list.shift #Get rid of the 'all' option
      return new_db_list
    end
  end

  # This class decides how this process works
  class Driver

    def initialize
      begin
        @opts = OptsConsole.parse(ARGV)
      rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
        print_error("#{e.message} (please see -h)")
        exit
      end

      @output_handle = nil
      begin
        @output_handle = ::File.new(@opts[:outfile], 'wb')
      rescue
        # Not end of the world, but if this happens we won't be able to save the results.
        # The user will just have to copy and paste from the screen.
        print_error("Unable to create file handle, results will not be saved to #{@opts[:output]}")
      end
    end

    # Main function
    #
    # @return [void]
    def run
      input = @opts[:input]
      dbs   = @opts[:databases]

      disclamer = Md5LookupUtility::Disclaimer.new

      unless disclamer.has_waiver?
        disclamer.ack
        disclamer.save_waiver
      end

      get_hash_results(input, dbs) do |result|
        original_hash = result[:hash]
        cracked_hash  = result[:cracked_hash]
        credit_db     = result[:credit]
        print_status("Found: #{original_hash} = #{cracked_hash} (from #{credit_db})")
        save_result(result) if @output_handle
      end
    end

    # Cleans up the output file handler if exists
    #
    # @return [void]
    def cleanup
      @output_handle.close if @output_handle
    end

    private

    # Saves the MD5 result to file
    #
    # @param result [Hash] The result that contains the MD5 information
    # @option result :hash [String] The original MD5 hash
    # @option result :cracked_hash [String] The cracked MD5 hash
    # @return [void]
    def save_result(result)
      @output_handle.puts "#{result[:hash]} = #{result[:cracked_hash]}"
    end

    # Returns the hash results by actually invoking Md5Lookup
    #
    # @param input [String] The path of the input file (MD5 hashes)
    # @yield [result] Gives a hash as the found result
    # @return [void]
    def get_hash_results(input, dbs)
      search_engine = Md5LookupUtility::Md5Lookup.new
      extract_hashes(input) do |hash|
        dbs.each do |db|
          cracked_hash = search_engine.lookup(hash, db)
          unless cracked_hash.empty?
            result = { :hash => hash, :cracked_hash => cracked_hash, :credit => db }
            yield result
          end

          # Awright, we already found one cracked, we don't need to keep looking,
          # Let's move on to the next hash!
          break unless cracked_hash.empty?
        end
      end
    end

    # Extracts all the MD5 hashes one by one
    #
    # @param input_file [String] The path of the input file (MD5 hashes)
    # @yield [hash] The original MD5 hash
    # @return [void]
    def extract_hashes(input_file)
      ::File.open(input_file, 'rb') do |f|
        f.each_line do |hash|
          next unless is_md5_format?(hash)
          yield hash.strip # Make sure no newlines
        end
      end
    end

    # Checks if the hash format is MD5 or not
    #
    # @param md5_hash [String] The MD5 hash (hex)
    # @return [TrueClass/FalseClass] True if the format is valid, otherwise false
    def is_md5_format?(md5_hash)
      (md5_hash =~ /^[a-f0-9]{32}$/i) ? true : false
    end
  end

end

#
# main
#
if __FILE__ == $PROGRAM_NAME
  driver = Md5LookupUtility::Driver.new
  begin
    driver.run
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  ensure
    driver.cleanup # Properly close resources
  end
end
