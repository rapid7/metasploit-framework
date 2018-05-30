=begin
 This script use run_cmd method from msf::base::sessions::meterpreter to execute meterpreter commands from terminal.
 This is a test script to verify the

=end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

# Adding Meterpreter file
require 'msf/base/sessions/meterpreter'

# user input and store it in a variable
# include a class from meterpreter.rb
# pass this variable as argument in run_cmd


class Run < Msf::Base::Sessions::Meterpreter
  def run(input)
    run_cmd(input)
    puts "Check Meterpreter for output"
  end
end

call=Run.new


puts "Enter the input from the user: "

call.run("getuid")


puts "Ending the module"