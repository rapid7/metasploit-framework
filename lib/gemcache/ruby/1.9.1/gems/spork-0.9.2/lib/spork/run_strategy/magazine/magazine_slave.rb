require 'rubygems'
require 'drb'
$:.unshift(File.dirname(__FILE__) + "/../../..")  # directory of spork.rb
require 'spork'

class MagazineSlave
  include DRb::DRbUndumped
  attr_reader :id_num
  def initialize(id_num, test_framework_short_name)
    @id_num = id_num
    @test_framework = Spork::TestFramework.factory(STDOUT, STDERR,
                                                   test_framework_short_name)
#    ENV["DRB"] = 'true'
#    Spork.using_spork!
    return(nil) unless preload
  end

  def run(argv, stderr, stdout)
    $stdout, $stderr = stdout, stderr
    Spork.exec_each_run
    load @test_framework.helper_file
    @test_framework.run_tests(argv, stderr, stdout)
    puts "  <-- Slave(#{@id_num}) run done!"; stdout.flush
  end

  def preload
    @test_framework.preload
  end

end