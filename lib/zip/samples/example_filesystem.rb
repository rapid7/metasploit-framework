#!/usr/bin/env ruby

$: << "../lib"

require 'zip/zipfilesystem'

EXAMPLE_ZIP = "filesystem.zip"

File.delete(EXAMPLE_ZIP) if File.exists?(EXAMPLE_ZIP)

Zip::ZipFile.open(EXAMPLE_ZIP, Zip::ZipFile::CREATE) {
  |zf|
  zf.file.open("file1.txt", "w") { |os| os.write "first file1.txt" }
  zf.dir.mkdir("dir1")
  zf.dir.chdir("dir1")
  zf.file.open("file1.txt", "w") { |os| os.write "second file1.txt" }
  puts zf.file.read("file1.txt")
  puts zf.file.read("../file1.txt")
  zf.dir.chdir("..")
  zf.file.open("file2.txt", "w") { |os| os.write "first file2.txt" }
  puts "Entries:                   #{zf.entries.join(', ')}"
}

Zip::ZipFile.open(EXAMPLE_ZIP) {
  |zf|
  puts "Entries from reloaded zip: #{zf.entries.join(', ')}"
}

# For other examples, look at zip.rb and ziptest.rb

# Copyright (C) 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
