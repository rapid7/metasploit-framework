#!/usr/bin/env ruby

# Lists the current count of modules, by type, and outputs a bare CSV.

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(framework_opts)
Indent = '  '

i = 0
module_types = {
  :exploit => 0,
  :auxiliary => 0,
  :post => 0,
  :payload => 0,
  :encoder => 0,
  :nop => 0
}

$framework.modules.each do |name, mod|
  this_mod = mod.new
  [:exploit, :auxiliary, :post, :payload, :encoder, :nop].each do |meth|
    interrogative = "#{meth}?".intern
    if this_mod.send(interrogative)
      module_types[meth] += 1 
    end
  end
end

puts module_types.keys.map {|k| k.to_s}.join(",")
puts module_types.values.join(",")
