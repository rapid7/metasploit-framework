#!/usr/bin/env ruby

$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), "..", "lib")))
require 'optparse'
require 'ostruct'
require 'recog'

def squash_lines(str)
  str.split(/\n/).join(' ').gsub(/\s+/, ' ')
end

def export_text(options)
end

def export_ruby(options)
  $stdout.puts "# Recog fingerprint database export [ #{File.basename(options.xml_file)} ] on #{Time.now.to_s}"
  $stdout.puts "fp_str   = '' # Set this value to the match string"
  $stdout.puts "fp_match = {} # Match results are stored here"
  $stdout.puts ""
  $stdout.puts "case fp_str"
  options.db.fingerprints.each do |fp|
    puts "  # #{squash_lines fp.name}"
    puts "  when /#{fp.regex.to_s}/"
    fp.tests.each do |test|
      puts "    # Example: #{squash_lines test}"
    end
    fp.params.each_pair do |k,v|
      if v[0] == 0
        puts "    fp_match[#{k.inspect}] = #{v[1].inspect}"
      else
        puts "    fp_match[#{k.inspect}] = $#{v[0].to_s}"
      end
    end
    puts ""
  end
  $stdout.puts "end"
end


options = OpenStruct.new(etype: :ruby)

option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] XML_FINGERPRINTS_FILE"
  opts.separator "Exports an XML fingerprint database to another format."
  opts.separator ""
  opts.separator "Options"

  opts.on("-t", "--type type", 
          "Choose a type of export.",
          "  [r]uby (default - export a ruby case statement with regular expressions)",
          "  [t]ext (export a text description of the fingerprints)") do |etype|
    case etype.downcase
    when /^r/
      options.etype = :ruby
    when /^t/
      options.etype = :text
    end
  end

  opts.on("-h", "--help", "Show this message.") do
    puts opts
    exit
  end
end
option_parser.parse!(ARGV)

if ARGV.count != 1
  puts option_parser
  exit
end

options.xml_file = ARGV.shift
options.db = Recog::DB.new(options.xml_file)

case options.etype
when :ruby
  export_ruby(options)
when :text
  export_text(options)
end

