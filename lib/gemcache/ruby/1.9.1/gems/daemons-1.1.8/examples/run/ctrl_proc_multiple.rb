lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'


options = {
  :log_output => true,
  :multiple => true, 
}


Daemons.run_proc('ctrl_proc_multiple.rb', options) do
  puts "hello"
  sleep(5)
  puts "done"
end