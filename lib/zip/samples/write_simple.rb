#!/usr/bin/env ruby

$: << "../lib"

require 'zip/zip'

include Zip

ZipOutputStream.open('simple.zip') {
  |zos|
  ze = zos.put_next_entry 'entry.txt'
  zos.puts "Hello world"
}
