lib_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../lib'))

if File.exist?(File.join(lib_dir, 'daemons.rb'))
  $LOAD_PATH.unshift lib_dir
else
  begin; require 'rubygems'; rescue ::Exception; end
end

require 'daemons'
require 'optparse'
require 'logger'
require 'ostruct'

class MyApp < Logger::Application
  def initialize(args)
    super(self.class)
    @options = OpenStruct.new(:daemonize => true)
    opts = OptionParser.new do |opts|
      opts.banner = 'Usage: myapp [options]'
      opts.separator ''
      opts.on('-N', '--no-daemonize', "Don't run as a daemon") do
        @options.daemonize = false
      end
    end
    @args = opts.parse!(args)
  end

  def run
    Daemons.run_proc('myapp', :ARGV => @args, :ontop => !@options.daemonize) do
      puts "@options.daemonize: #{@options.daemonize}"
      $stdout.sync = true
      loop do
        print '.'
        sleep(2)
      end
    end
  end
end

myapp = MyApp.new(ARGV)
myapp.run
