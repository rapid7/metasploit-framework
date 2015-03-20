msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'
require 'rex'
require 'msf/core'
require 'optparse'

module Egghunter
  class Driver < Msf::Auxiliary
    include Msf::Exploit::Remote::Egghunter

    def initialize(opts={})
    end

    def run
    end

  end
end


if __FILE__ == $PROGRAM_NAME
  driver = Egghunter::Driver.new
  begin
    driver.run
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  end
end