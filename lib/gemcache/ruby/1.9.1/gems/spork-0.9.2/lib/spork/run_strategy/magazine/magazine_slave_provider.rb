# magazine_slave_provider.rb
require 'drb'
require 'rinda/ring'
require 'rinda/tuplespace'
require './magazine_slave'



# pass on

id = ARGV[0].to_i || "?"
app_pwd = ARGV[1]
test_framework_short_name = ARGV[2]

# start up the Rinda service

DRb.start_service

Dir.chdir app_pwd
puts "   -- build slave #{id}..."; $stdout.flush
magazine_slave = MagazineSlave.new(id, test_framework_short_name )

# never expire, the renewer returns nil, which means expiration of *nix clock
renewer = Rinda::SimpleRenewer.new(nil)
Rinda::RingProvider.new(:MagazineSlave, magazine_slave, id, renewer).provide

puts "  --> DRb magazine_slave_service: #{id} provided..."; $stdout.flush

# wait for the DRb service to finish before exiting
DRb.thread.join