lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'

options = {
  :log_output => true
}

testfile = File.expand_path(__FILE__) + '.txt'

Daemons.daemonize(options)

puts 'some output...'

File.open(testfile, 'w') do |f|
  f.write('test')
end
