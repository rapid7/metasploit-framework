#!/usr/bin/env ruby

# This is myserver.rb, an example server that is to be controlled by daemons
# and that does nothing really useful at the moment.
#
# Don't run this script by yourself, it can be controlled by the ctrl*.rb scripts.

loop do
  puts 'ping from myserver.rb!'
  sleep(3)
end
