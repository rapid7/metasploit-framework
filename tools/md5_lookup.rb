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

def print_status(msg='')
  $stdout.puts "[*] #{msg}"
end


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

    def initialize
      self.rhost      = 'md5cracker.org'
      self.rport      = 80
      self.target_uri = '/api/api.cracker.php'
      self.out_file   = opts[:out_file] || 'results.txt'
      self.databases  = opts[:databases]
    end
  end

  class Md5Lookup < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient

    def initialize(opts={})
      super
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
          :all           => nil, # If all, this is shifted
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
    # @return [Array] The normalized options
    def self.parse(args)
      options = {}

      opts = OptionParser.new do |opt|

        opt.banner = "Usage: #{__FILE__} [options]"
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-i', '--input <file>', 'The file that contains all the MD5 hashes') do |v|
          if v && !::File.exists?(v)
            print_error("Invalid input file: #{v}")
            exit
          end

          options[:input] = v
        end

        opt.on('-d','--databases <list>', "Select databases: #{get_database_symbols * ", "}") do |v|
          options[:databases] = extract_db_names(v)
        end

        opt.separator ''
        opt.separator 'Common options:'

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end

      if !options[:databases]
        options[:databases] = get_database_names
      end

      begin
        opts.parse!(args)
      rescue OptionParser::InvalidOption
        print_error("Invallid option, try -h for usage")
        exit
      end

      if options.empty?
        print_error("No options set, try -h for usage")
        exit
      end

      options
    end

    private


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
    def self.get_database_symbols
      DATABASES.keys
    end

    # Returns a list of all the original database values recognized by md5cracker.org
    def self.get_database_names
      new_db_list = DATABASES.values
      new_db_list.shift #Get rid of the 'all' option
      return new_db_list
    end
  end


  # This class is the driver
  class Driver
    def initialize
      opts = {}
      options = OptsConsole.parse(ARGV)
      puts options.inspect
    end
  end

end


#
# main
#
if __FILE__ == $PROGRAM_NAME
  begin
    driver = Md5LookupUtility::Driver.new
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  end
end