# ring_server.rb
require 'rinda/ring'
require 'rinda/tuplespace'

DRb.start_service

Rinda::RingServer.new(Rinda::TupleSpace.new)
puts "  -- Rinda Ring Server listening for connections...\n\n"
$stdout.flush
DRb.thread.join
