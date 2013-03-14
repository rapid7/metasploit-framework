lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'

options = {
  #:mode => :exec,
  :multiple => true,
  :no_pidfiles => true,
  :force_kill_waittime => 5
  #:force_kill_waittime => -1    # do not wait before killing -9
}

Daemons.run(File.join(File.dirname(__FILE__), 'myserver_hanging.rb'), options)
