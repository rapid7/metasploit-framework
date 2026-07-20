#!/usr/bin/env ruby

require 'find'

def report_non_ascii(file_path)
  has_errors = false
  File.foreach(file_path).with_index(1) do |line, line_number|
    line_utf8 = line.force_encoding('UTF-8')
    next unless line_utf8.valid_encoding?

    line_utf8.chars.each_with_index do |char, index|
      unless char.ascii_only?
        has_errors = true
        puts "Error - non-ascii character found. #{file_path}: line #{line_number}, char #{index+1} => #{char.inspect}"
      end
    end
  end
  has_errors
end

path_to_search = File.expand_path(File.join(__FILE__, '..', '..', '..'))
puts "Verifying binary encoding files in '#{path_to_search}' do not contain non-ASCII characters..."

has_errors = false
ran_at_least_once = false

# Walk all files
Find.find(path_to_search) do |path|
  next unless File.file?(path)
  next if path.include?('/vendor/')
  next unless path.end_with?('.rb')

  # Only check files that declare binary encoding
  first_two_lines = File.open(path, "r") { |f| f.each_line.take(2).join }
  next unless first_two_lines =~ /coding:\s*binary/

  ran_at_least_once = true
  has_errors |= report_non_ascii(path)
end

if !ran_at_least_once
  puts "Did not run on any files, did not find any files with binary encoding declaration. Please check the script and ensure it is looking for the correct encoding declaration."
  exit(1)
end

if has_errors
  puts "Finished with errors. Please fix the above issues and run again."
  exit(1)
end

puts "Finished without errors"

