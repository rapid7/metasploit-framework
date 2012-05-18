require 'rack'
require 'rack/server'
require 'tempfile'
require 'socket'
require 'open-uri'

describe Rack::Server do

  def app
    lambda { |env| [200, {'Content-Type' => 'text/plain'}, ['success']] }
  end

  it "overrides :config if :app is passed in" do
    server = Rack::Server.new(:app => "FOO")
    server.app.should == "FOO"
  end

  should "not include Rack::Lint in deployment or none environments" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['deployment'].flatten.should.not.include(Rack::Lint)
    server.middleware['none'].flatten.should.not.include(Rack::Lint)
  end

  should "not include Rack::ShowExceptions in deployment or none environments" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['deployment'].flatten.should.not.include(Rack::ShowExceptions)
    server.middleware['none'].flatten.should.not.include(Rack::ShowExceptions)
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

  should "not force any middleware under the none configuration" do
    server = Rack::Server.new(:app => 'foo')
    server.middleware['none'].should.be.empty
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

end
