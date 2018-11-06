#!/usr/bin/env ruby

# This is myserver_slowstop.rb, an example server that is to be controlled by daemons
# and that does nothing really useful at the moment.
#
# Don't run this script by yourself, it can be controlled by the ctrl*.rb scripts.

trap('TERM') do
  puts 'received TERM'

  # simulate the slow stopping
  sleep(10)

  exit
end

loop do
  puts 'ping from myserver.rb!'
  sleep(3)
end
