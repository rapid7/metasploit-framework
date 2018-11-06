require 'rack'
require 'rack/server'
require 'tempfile'
require 'socket'
require 'open-uri'

describe Rack::Server do

  def app
    lambda { |env| [200, {'Content-Type' => 'text/plain'}, ['success']] }
  end

  def with_stderr
    old, $stderr = $stderr, StringIO.new
    yield $stderr
  ensure
    $stderr = old
  end

  it "overrides :config if :app is passed in" do
    server = Rack::Server.new(:app => "FOO")
    server.app.should.equal "FOO"
  end

  should "prefer to use :builder when it is passed in" do
    server = Rack::Server.new(:builder => "run lambda { |env| [200, {'Content-Type' => 'text/plain'}, ['success']] }")
    server.app.class.should.equal Proc
    Rack::MockRequest.new(server.app).get("/").body.to_s.should.equal 'success'
  end

  should "allow subclasses to override middleware" do
    server = Class.new(Rack::Server).class_eval { def middleware; Hash.new [] end; self }
    server.middleware['deployment'].should.not.equal []
    server.new(:app => 'foo').middleware['deployment'].should.equal []
  end

  should "allow subclasses to override default middleware" do
    server = Class.new(Rack::Server).instance_eval { def default_middleware_by_environment; Hash.new [] end; self }
    server.middleware['deployment'].should.equal []
    server.new(:app => 'foo').middleware['deployment'].should.equal []
  end

  should "only provide default middleware for development and deployment environments" do
    Rack::Server.default_middleware_by_environment.keys.sort.should.equal %w(deployment development)
  end

  should "always return an empty array for unknown environments" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['production'].should.equal []
  end

  should "not include Rack::Lint in deployment environment" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['deployment'].flatten.should.not.include(Rack::Lint)
  end

  should "not include Rack::ShowExceptions in deployment environment" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['deployment'].flatten.should.not.include(Rack::ShowExceptions)
  end

  should "include Rack::TempfileReaper in deployment environment" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['deployment'].flatten.should.include(Rack::TempfileReaper)
  end

  should "support CGI" do
    begin
      o, ENV["REQUEST_METHOD"] = ENV["REQUEST_METHOD"], 'foo'
      server = Rack::Server.new(:app => 'foo')
      server.server.name =~ /CGI/
      Rack::Server.logging_middleware.call(server).should.eql(nil)
    ensure
      ENV['REQUEST_METHOD'] = o
    end
  end

  should "be quiet if said so" do
    server = Rack::Server.new(:app => "FOO", :quiet => true)
    Rack::Server.logging_middleware.call(server).should.eql(nil)
  end

  should "use a full path to the pidfile" do
    # avoids issues with daemonize chdir
    opts = Rack::Server.new.send(:parse_options, %w[--pid testing.pid])
    opts[:pid].should.eql(::File.expand_path('testing.pid'))
  end

  should "run a server" do
    pidfile = Tempfile.open('pidfile') { |f| break f }.path
    FileUtils.rm pidfile
    server = Rack::Server.new(
      :app         => app,
      :environment => 'none',
      :pid         => pidfile,
      :Port        => TCPServer.open('127.0.0.1', 0){|s| s.addr[1] },
      :Host        => '127.0.0.1',
      :daemonize   => false,
      :server      => 'webrick'
    )
    t = Thread.new { server.start { |s| Thread.current[:server] = s } }
    t.join(0.01) until t[:server] && t[:server].status != :Stop
    body = open("http://127.0.0.1:#{server.options[:Port]}/") { |f| f.read }
    body.should.eql('success')

    Process.kill(:INT, $$)
    t.join
    open(pidfile) { |f| f.read.should.eql $$.to_s }
  end

  should "check pid file presence and running process" do
    pidfile = Tempfile.open('pidfile') { |f| f.write($$); break f }.path
    server = Rack::Server.new(:pid => pidfile)
    server.send(:pidfile_process_status).should.eql :running
  end

  should "check pid file presence and dead process" do
    dead_pid = `echo $$`.to_i
    pidfile = Tempfile.open('pidfile') { |f| f.write(dead_pid); break f }.path
    server = Rack::Server.new(:pid => pidfile)
    server.send(:pidfile_process_status).should.eql :dead
  end

  should "check pid file presence and exited process" do
    pidfile = Tempfile.open('pidfile') { |f| break f }.path
    ::File.delete(pidfile)
    server = Rack::Server.new(:pid => pidfile)
    server.send(:pidfile_process_status).should.eql :exited
  end

  should "check pid file presence and not owned process" do
    pidfile = Tempfile.open('pidfile') { |f| f.write(1); break f }.path
    server = Rack::Server.new(:pid => pidfile)
    server.send(:pidfile_process_status).should.eql :not_owned
  end

  should "not write pid file when it is created after check" do
    pidfile = Tempfile.open('pidfile') { |f| break f }.path
    ::File.delete(pidfile)
    server = Rack::Server.new(:pid => pidfile)
    ::File.open(pidfile, 'w') { |f| f.write(1) }
    with_stderr do |err|
      should.raise(SystemExit) do
        server.send(:write_pid)
      end
      err.rewind
      output = err.read
      output.should.match(/already running/)
      output.should.include? pidfile
    end
  end

  should "inform the user about existing pidfiles with running processes" do
    pidfile = Tempfile.open('pidfile') { |f| f.write(1); break f }.path
    server = Rack::Server.new(:pid => pidfile)
    with_stderr do |err|
      should.raise(SystemExit) do
        server.start
      end
      err.rewind
      output = err.read
      output.should.match(/already running/)
      output.should.include? pidfile
    end
  end

end
