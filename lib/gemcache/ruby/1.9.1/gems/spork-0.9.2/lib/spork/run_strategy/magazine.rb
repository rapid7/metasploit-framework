# this class' goal:
# to boldly just run test after test
# as they come in
require 'drb'
require 'rinda/ring'
if RUBY_PLATFORM =~ /mswin|mingw/  and RUBY_VERSION < '1.9.1'
  begin
    require 'win32/process'
  rescue LoadError
    puts "The 'win32-process' gem is required for windows Spork support with ruby 1.9.1 and lower. Install it, or if using bundler, add it to your Gemfile."
    exit 1
  end
end

require 'rubygems' # used for Gem.ruby

$:.unshift(File.dirname(__FILE__))
require 'magazine/magazine_slave'

class Spork::RunStrategy::Magazine < Spork::RunStrategy

  Slave_Id_Range = 1..2 # Ringserver uses id: 0. Slave use: 1..MAX_SLAVES

  def slave_max
    Slave_Id_Range.to_a.size
  end

  def initialize(test_framework)
    @test_framework = test_framework
    this_path = File.expand_path(File.dirname(__FILE__))
    @path = File.join(this_path, 'magazine')
    @pids = []

    @pids << start_Rinda_ringserver
    sleep 1

    fill_slave_pool
  rescue RuntimeError => e
    kill_all_processes
    raise e
  end

  def start_Rinda_ringserver
    app_name = "#{Gem.ruby} ring_server.rb"
    spawn_process(app_name)
  end

  def fill_slave_pool
    Slave_Id_Range.each do |id|
      start_slave(id)
    end
    puts "  -- Starting to fill pool..."
    puts "     Wait until at least one slave is provided before running tests..."
    puts "  ** CTRL+BREAK to stop Spork and kill all ruby slave processes **"
    $stdout.flush
  end

  def start_slave(id)
    app_pwd = Dir.pwd  # path running app in
    app = "#{Gem.ruby} magazine_slave_provider.rb #{id} '#{app_pwd}' #{@test_framework.short_name}"
    @pids[id] = spawn_process(app)
  end

  def spawn_process(app)

    if RUBY_PLATFORM =~ /java/
      # jruby 1.8 has no easy way to just spawn, so use a thread
      Dir.chdir(@path) do
        io = IO.popen app
        Thread.new { puts io.read }        
        return io.pid
      end
    end
    
    if RUBY_VERSION < '1.9.1'
      Process.create( :app_name => app, :cwd => @path ).process_id
    else
      Process.spawn( app, :chdir => @path )
    end
  end

  def self.available?
    true
  end

  def run(argv, stderr, stdout)
        DRb.start_service
        ts = Rinda::RingFinger.primary
        if ts.read_all([:name, :MagazineSlave, nil, nil]).size > 0
          print '  <-- take tuple'; stdout.flush
          tuple = ts.take([:name, :MagazineSlave, nil, nil])
          slave = tuple[2]
          id = tuple[3]

          puts "(#{slave.id_num}); slave.run..."; $stdout.flush
          begin
            slave.run(argv,stderr,stdout)
            puts "   -- (#{slave.id_num});run done"; $stdout.flush
          ensure
            restart_slave(id)
          end
        else
          puts '- NO tuple'; $stdout.flush
        end
  end

  def restart_slave(id)
    pid   = @pids[id]
    kill_slave(pid)
    start_slave(id)
  end

  def windows?
    ENV['OS'] == 'Windows_NT'
  end

  def kill_slave(pid)
    if windows?
      system("taskkill /f /t /pid #{pid} > nul")
    else
      Process.kill(9, pid)
    end
  end
  
  def kill_all_processes

    @pids.each {|pid| 
      kill_slave(pid)
    }
    puts "\nKilling processes."; $stdout.flush
  end

  def slave_count
    DRb.start_service
    ts = Rinda::RingFinger.primary
    ts.read_all([:name, :MagazineSlave, nil, nil]).size
  end


  def abort
    kill_all_processes
  end

  def preload
    true
    #    @test_framework.preload
  end

  def running?
    @running
  end

  def assert_ready!
  end
end
