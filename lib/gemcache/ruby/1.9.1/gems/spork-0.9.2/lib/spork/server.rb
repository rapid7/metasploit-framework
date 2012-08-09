require 'drb/drb'
require 'rbconfig'
require 'spork/forker.rb'
require 'spork/custom_io_streams.rb'
require 'spork/app_framework.rb'

# An abstract class that is implemented to create a server
#
# (This was originally based off of spec_server.rb from rspec-rails (David Chelimsky), which was based on Florian Weber's TDDMate)
class Spork::Server
  attr_reader :run_strategy
  include Spork::CustomIOStreams
  
  def initialize(options = {})
    @run_strategy = options[:run_strategy]
    @port = options[:port]
  end
  
  def self.run(options = {})
    new(options).listen
  end
  
  # Sets up signals and starts the DRb service. If it's successful, it doesn't return. Not ever.  You don't need to override this.
  def listen
    @run_strategy.assert_ready!
    trap("SIGINT") { sig_int_received }
    trap("SIGTERM") { abort; exit!(0) }
    trap("USR2") { abort; restart } if Signal.list.has_key?("USR2")
    @drb_service = DRb.start_service("druby://127.0.0.1:#{port}", self)
    Spork.each_run { @drb_service.stop_service } if @run_strategy.class == Spork::RunStrategy::Forking
    stderr.puts "Spork is ready and listening on #{port}!"
    stderr.flush
    DRb.thread.join
  end
  
  attr_accessor :port

  # This is the public facing method that is served up by DRb.  To use it from the client side (in a testing framework):
  # 
  #   DRb.start_service("druby://localhost:0") # this allows Ruby to do some magical stuff so you can pass an output stream over DRb.
  #                                            # see http://redmine.ruby-lang.org/issues/show/496 to see why localhost:0 is used.
  #   spec_server = DRbObject.new_with_uri("druby://127.0.0.1:8989")
  #   spec_server.run(options.argv, $stderr, $stdout)
  #
  # When implementing a test server, don't override this method: override run_tests instead.
  def run(argv, stderr, stdout)
    puts "Running tests with args #{argv.inspect}..."
    result = run_strategy.run(argv, stderr, stdout)
    puts "Done.\n\n"
    result
  end
  
  def abort
    run_strategy.abort
  end

  private
    def restart
      stderr.puts "restarting"
      stderr.flush
      config       = ::Config::CONFIG
      ruby         = File::join(config['bindir'], config['ruby_install_name']) + config['EXEEXT']
      command_line = [ruby, $0, ARGV].flatten.join(' ')
      exec(command_line)
    end
    
    def sig_int_received
      stdout.puts "\n"
      abort
      if run_strategy.running?
        stderr.puts "Running tests stopped.  Press CTRL-C again to stop the server."
        stderr.flush
      else
        exit!(0)
      end
    end
end
