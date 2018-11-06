#!/usr/bin/env ruby

$: << '../lib'

require 'zip'

include Zip

OutputStream.open('simple.zip') do |zos|
  zos.put_next_entry 'entry.txt'
  zos.puts 'Hello world'
end
