msfbase = __FILE__
while File.symlink?(msfbas)
  msfbase = File.expand_path(File.readlink(msfbase),File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase),['..','..','..','lib'])))

require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require ''