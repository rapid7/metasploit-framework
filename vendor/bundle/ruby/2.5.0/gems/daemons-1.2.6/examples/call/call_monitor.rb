lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'

testfile = File.expand_path(__FILE__) + '.log'

# On the first call to <tt<call</tt>, an application group (accessible by <tt>Daemons.group</tt>)
# will be created an the options will be kept within, so you only have to specify
# <tt>:multiple</tt> once.
#

options = {
#  :ontop => true,
  :multiple => true,
  :monitor => true
}

Daemons.call(options) do
  loop { puts '1'; sleep 20 }
end
puts 'first task started'

# NOTE: this process will exit after 5 seconds
Daemons.call do
  File.open(testfile, 'a') do |f|
    f.puts 'started...'
    puts '2'

    sleep 5

    f.puts '...exit'
  end
end
puts 'second task started'

puts 'waiting 100 seconds...'
sleep(100)

# This call would result in an exception as it will try to kill the third process
# which has already terminated by that time; but using the 'true' parameter forces the
# stop_all procedure.
puts 'trying to stop all tasks...'
Daemons.group.stop_all(true)

puts 'done'
