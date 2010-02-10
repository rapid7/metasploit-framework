#!/usr/bin/env ruby

#
# Add a file from memory and save it.
#

require 'zip'

# example usage
zip = Zip::Archive.new
zip.add_file("elite.txt", "A" * 1024)
zip.save_to("lolz.zip")
