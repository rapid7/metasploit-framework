lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'

Daemons.run_proc('myscript') do
  loop do
    file = File.open('/tmp/myscript.log', 'a')
    file.write(Random.rand)   # breaks without seeding
    # file.write(Random.new.rand)  # works without seeding
    # file.write(rand) # also works, but this is Kernel.rand() so its different
    file.write("\n")
    file.close
    sleep 2
  end
end
