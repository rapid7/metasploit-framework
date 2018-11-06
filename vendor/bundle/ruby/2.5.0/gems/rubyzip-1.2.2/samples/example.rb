#!/usr/bin/env ruby

$: << '../lib'
system('zip example.zip example.rb gtk_ruby_zip.rb')

require 'zip'

####### Using ZipInputStream alone: #######

Zip::InputStream.open('example.zip') do |zis|
  entry = zis.get_next_entry
  print "First line of '#{entry.name} (#{entry.size} bytes):  "
  puts "'#{zis.gets.chomp}'"
  entry = zis.get_next_entry
  print "First line of '#{entry.name} (#{entry.size} bytes):  "
  puts "'#{zis.gets.chomp}'"
end

####### Using ZipFile to read the directory of a zip file: #######

zf = Zip::File.new('example.zip')
zf.each_with_index do |entry, index|
  puts "entry #{index} is #{entry.name}, size = #{entry.size}, compressed size = #{entry.compressed_size}"
  # use zf.get_input_stream(entry) to get a ZipInputStream for the entry
  # entry can be the ZipEntry object or any object which has a to_s method that
  # returns the name of the entry.
end

####### Using ZipOutputStream to write a zip file: #######

Zip::OutputStream.open('exampleout.zip') do |zos|
  zos.put_next_entry('the first little entry')
  zos.puts 'Hello hello hello hello hello hello hello hello hello'

  zos.put_next_entry('the second little entry')
  zos.puts 'Hello again'

  # Use rubyzip or your zip client of choice to verify
  # the contents of exampleout.zip
end

####### Using ZipFile to change a zip file: #######

Zip::File.open('exampleout.zip') do |zip_file|
  zip_file.add('thisFile.rb', 'example.rb')
  zip_file.rename('thisFile.rb', 'ILikeThisName.rb')
  zip_file.add('Again', 'example.rb')
end

# Lets check
Zip::File.open('exampleout.zip') do |zip_file|
  puts "Changed zip file contains: #{zip_file.entries.join(', ')}"
  zip_file.remove('Again')
  puts "Without 'Again': #{zip_file.entries.join(', ')}"
end

####### Using ZipFile to split a zip file: #######

# Creating large zip file for splitting
Zip::OutputStream.open('large_zip_file.zip') do |zos|
  puts 'Creating zip file...'
  10.times do |i|
    zos.put_next_entry("large_entry_#{i}.txt")
    zos.puts 'Hello' * 104_857_600
  end
end

# Splitting created large zip file
part_zips_count = Zip::File.split('large_zip_file.zip', 2_097_152, false)
puts "Zip file splitted in #{part_zips_count} parts"

# Track splitting an archive
Zip::File.split('large_zip_file.zip', 1_048_576, true, 'part_zip_file') do |part_count, part_index, chunk_bytes, segment_bytes|
  puts "#{part_index} of #{part_count} part splitting: #{(chunk_bytes.to_f / segment_bytes.to_f * 100).to_i}%"
end

# For other examples, look at zip.rb and ziptest.rb

# Copyright (C) 2002 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
