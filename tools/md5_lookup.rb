#!/usr/bin/env ruby

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This script will look up a collection of MD5 hashes (from a file) against the following databases
# via md5cracker.org:
# authsecu, i337.net, md5.my-addr.com, md5.net, md5crack, md5cracker.org, md5decryption.com,
# md5online.net, md5pass, netmd5crack, tmto.
# This was originally ported from:
# https://github.com/hasherezade/metasploit_modules/blob/master/md5_lookup.rb
#
# Authors:
# * hasherezade (original work)
# * sinn3r (ported the module as a standalone msf tool)
#
###

#
# Load our MSF API
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'
require 'rex'
require 'msf/core'
require 'optparse'


#
# Basic prints we can't live without
#

# Prints with [*] that represents the message is a status
def print_status(msg='')
  $stdout.puts "[*] #{msg}"
end

# Prints with [-] that represents the message is an error
def print_error(msg='')
  $stdout.puts "[-] #{msg}"
end

module Md5LookupUtility

  # This class provides the basic settings required for the utility
  class Config
    # @!attribute rhost
    #  @return [String] Should be md5cracker.org
    attr_accessor :rhost

    # @!attribute rport
    #  @return [Fixnum] The port number
    attr_accessor :rport

    # @!attribute target_uri
    #  @return [String] The URI
    attr_accessor :target_uri

    # @!attribute out_file
    #  @return [String] The output file path (to save the cracked MD5 results)
    attr_accessor :out_file

    def initialize(opts={})
      self.rhost      = 'md5cracker.org'
      self.rport      = 80
      self.target_uri = '/api/api.cracker.php'
      self.out_file   = opts[:out_file] || 'results.txt'
    end
  end


  # This class is basically an auxiliary module without relying on msfconsole
  class Md5Lookup < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient

    def initialize(opts={})
      @config = Md5LookupUtility::Config.new

      super(
        'DefaultOptions' =>
          {
            'SSL'   => false, # Doesn't look like md5cracker.org supports HTTPS
            'RHOST' => resolve_host(@config.rhost),
            'RPORT' => @config.rport
          }
      )
    end


    # Returns the look up HTTP response
    # @param md5_hash [String] The MD5 hash to lookup
    # @param db_names [String] The databases check
    def lookup(md5_hash, db_names)
      send_request_cgi({
        'uri' => Md5LookupUtility::Config.target_uri,
        'method' => 'GET',
        'vars_get' => {'database'=> db_names, 'hash'=>md5_hash}
      })
    end

    private

    # Returns the resolved md5cracker.org host.
    # If for some reason the method cannot resolve the DNS, return the default one: 144.76.226.137
    # @param host [String] The md5cracker.org host
    # @return [String] IP address
    def resolve_host(host)
      Rex::Socket.resolv_to_dotted(host) rescue '144.76.226.137'
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

    # Parses the user inputs
    # @param args [Array] This should be Ruby's ARGV
    # @raise [OptionParser::MissingArgument] Missing arguments
    # @return [Array] The normalized options
    def self.parse(args)
      parser, options = get_parsed_options

      # Set the optional datation argument (--database)
      if !options[:databases]
        options[:databases] = get_database_names
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
    # raise [OptionParser::InvalidOption] Invalid option found
    # @return [Array] The OptionParser object and an array of options
    def self.get_parsed_options
      options = {}
      parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options]"
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-i', '--input <file>',
          'The file that contains all the MD5 hashes (one line per hash)') do |v|
          if v && !::File.exists?(v)
            raise OptionParser::InvalidOption, "Invalid input file: #{v}"
          end

          options[:input] = v
        end

        opt.on('-d','--databases <names>',
          "(Optional) Select databases: #{get_database_symbols * ", "} (Default=all)") do |v|
          options[:databases] = extract_db_names(v)
        end

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end
      return parser, options
    end


    # Returns the actual database names based on what the user wants
    # @param list [String] A list of user-supplied database names
    # @return [Array] All the matched database names
    def self.extract_db_names(list)
      new_db_list = []

      if list.split(',').include?('all')
        return get_database_names
      end

      list.split(',').each do |item|
        item = item.to_sym
        new_db_list << DATABASES[item] if DATABASES[item]
      end

      new_db_list
    end


    # Returns a list of all of the supported database symbols
    # @return [Array] Database symbols
    def self.get_database_symbols
      DATABASES.keys
    end

    # Returns a list of all the original database values recognized by md5cracker.org
    # @return [Array] Original database values
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
    end


    # Main function
    def run
      input = @opts[:input]
      dbs   = @opts[:databases]

      get_hash_results(input) do |result|
        original_hash = result[:hash]
        cracked_hash  = result[:cracked_hash]
      end
    end

    private

    # Returns the hash results by actually invoking Md5Lookup
    def get_hash_results(input)
      search_engine = Md5LookupUtility::Md5Lookup.new
      extract_hashes(input) do |hash|
        $stderr.puts hash.inspect
      end
    end

    # Extracts all the MD5 hashes one by one
    def extract_hashes(input_file)
      ::File.open(input_file, 'rb') do |f|
        f.each_line do |hash|
          next if !is_md5_format?(hash)
          yield hash.strip # Make sure no newlines
        end
      end
    end

    # Checks if the hash format is MD5 or not
    # @param md5_hash [String] The MD5 hash (hex)
    # @return [TrueClass/FlaseClass] True if the format is valid, otherwise false
    def is_md5_format?(md5_hash)
      (md5_hash =~ /^[a-f0-9]{32}$/i) ? true : false
    end
  end

end


#
# main
#
if __FILE__ == $PROGRAM_NAME
  begin
    driver = Md5LookupUtility::Driver.new
    driver.run
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  end
end