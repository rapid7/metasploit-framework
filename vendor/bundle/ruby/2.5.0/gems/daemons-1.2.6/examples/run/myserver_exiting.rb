loop do
  puts 'ping from myserver.rb!'
  puts 'this example server will exit in 3 seconds...'

  sleep(3)

  Process.exit
end
