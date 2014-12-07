#!/usr/bin/env ruby

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

msf_base = __FILE__
while File.symlink?(msf_base)
  msf_base = File.expand_path(File.readlink(msf_base), File.dirname(msf_base))
end

$:.unshift(File.expand_path(File.join(File.dirname(msf_base), '..', 'lib')))
require 'rex/java/serialization'
require 'pp'

# This class allows to deserialize Java Streams from
# files
class JavaDeserializer

  # @!attribute file
  #   @return [String] the file's path to deserialize
  attr_accessor :file

  # @param file [String] the file's path to deserialize
  def initialize(file = nil)
    self.file = file
  end

  # Deserializes a Java stream from a file and prints the result.
  #
  # @return [Rex::Java::Serialization::Model::Stream] if succeeds
  # @return [nil] if error
  def run
    if file.nil?
      print_error("file path with serialized java stream required")
      return
    end

    print_status("Deserializing...")
    print_line

    begin
      f = File.new(file, 'rb')
      stream = Rex::Java::Serialization::Model::Stream.decode(f)
      f.close
    rescue ::Exception => e
      print_exception(e)
      return
    end

    puts stream
  end

  private

  # @param [String] string to print as status
  def print_status(msg='')
    $stdout.puts "[*] #{msg}"
  end

  # @param [String] string to print as error
  def print_error(msg='')
    $stdout.puts "[-] #{msg}"
  end

  # @param [Exception] exception to print
  def print_exception(e)
    print_error(e.message)
    e.backtrace.each do |line|
      $stdout.puts("\t#{line}")
    end
  end

  def print_line
    $stdout.puts("\n")
  end
end

if __FILE__ == $PROGRAM_NAME
  deserializer = JavaDeserializer.new(ARGV[0])
  deserializer.run
end
