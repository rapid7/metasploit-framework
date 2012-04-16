require File.dirname(__FILE__) + '/spec_helper'

describe Server do
  before do
    @server = Server.new('0.0.0.0', 3000)
  end
  
  it "should set maximum_connections size" do
    @server.maximum_connections = 100
    @server.config
    @server.maximum_connections.should == 100
  end

  it "should set lower maximum_connections size when too large" do
    # root users under Linux will not have a limitation on maximum
    # connections, so we cannot really run this test under that
    # condition.
    pending("only for non-root users") if Process.euid == 0
    @server.maximum_connections = 100_000
    @server.config
    @server.maximum_connections.should < 100_000
  end
  
  it "should default to non-threaded" do
    @server.should_not be_threaded
  end
  
  it "should set backend to threaded" do
    @server.threaded = true
    @server.backend.should be_threaded
  end
end

describe Server, "initialization" do
  it "should set host and port" do
    server = Server.new('192.168.1.1', 8080)

    server.host.should == '192.168.1.1'
    server.port.should == 8080
  end

  it "should set socket" do
    server = Server.new('/tmp/thin.sock')

    server.socket.should == '/tmp/thin.sock'
  end
  
  it "should set host, port and app" do
    app = proc {}
    server = Server.new('192.168.1.1', 8080, app)
    
    server.host.should_not be_nil
    server.app.should == app
  end

  it "should set socket and app" do
    app = proc {}
    server = Server.new('/tmp/thin.sock', app)
    
    server.socket.should_not be_nil
    server.app.should == app
  end

  it "should set socket, nil and app" do
    app = proc {}
    server = Server.new('/tmp/thin.sock', nil, app)
    
    server.socket.should_not be_nil
    server.app.should == app
  end
  
  it "should set host, port and backend" do
    server = Server.new('192.168.1.1', 8080, :backend => Thin::Backends::SwiftiplyClient)
    
    server.host.should_not be_nil
    server.backend.should be_kind_of(Thin::Backends::SwiftiplyClient)
  end  

  it "should set host, port, app and backend" do
    app = proc {}
    server = Server.new('192.168.1.1', 8080, app, :backend => Thin::Backends::SwiftiplyClient)
    
    server.host.should_not be_nil
    server.app.should == app
    server.backend.should be_kind_of(Thin::Backends::SwiftiplyClient)
  end
  
  it "should set port as string" do
    app = proc {}
    server = Server.new('192.168.1.1', '8080')
    
    server.host.should == '192.168.1.1'
    server.port.should == 8080
  end
  
  it "should not register signals w/ :signals => false" do
    Server.should_not_receive(:setup_signals)
    Server.new(:signals => false)
  end
end