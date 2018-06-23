=begin
This File will retrieve List of POST Exploitation Modules from MSF console
and Extension commands from meterpreter shell. Data will be dumped in JSon
format Using Json class in serializer.
=end


msfbase = __FILE__

while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readline(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..','..','..','lib')))
require 'lib/msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'lib/msf/base'