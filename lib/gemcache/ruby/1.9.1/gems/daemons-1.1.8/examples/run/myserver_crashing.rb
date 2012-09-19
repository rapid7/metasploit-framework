# This is myserver.rb, an example server that is to be controlled by daemons
# and that does nothing really useful at the moment.
#
# Don't run this script by yourself, it can be controlled by the ctrl*.rb scripts.

loop do
  puts 'ping from myserver.rb!'
  puts 'this example server will crash in 3 seconds...'
  
  sleep(3)
  
  puts 'CRASH!'
  raise 'CRASH!'
end
