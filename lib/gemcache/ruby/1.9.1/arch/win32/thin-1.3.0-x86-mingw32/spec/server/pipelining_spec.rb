require File.dirname(__FILE__) + '/../spec_helper'

describe Server, "HTTP pipelining" do
  before do
    calls = 0
    start_server do |env|
      calls += 1
      body = env['PATH_INFO'] + '-' + calls.to_s
      [200, { 'Content-Type' => 'text/html' }, body]
    end
    @server.maximum_persistent_connections = 1024
  end
  
  it "should pipeline request on same socket" do
    socket = TCPSocket.new('0.0.0.0', 3333)
    socket.write "GET /first HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"
    socket.flush
    socket.write "GET /second HTTP/1.1\r\nConnection: close\r\n\r\n"
    socket.flush
    response = socket.read
    socket.close
    
    wait_for_requests_to_complete!
    
    response.should include('/first-1', '/second-2')
  end
  
  it "should pipeline requests by default on HTTP 1.1" do
    socket = TCPSocket.new('0.0.0.0', 3333)
    socket.write "GET /first HTTP/1.1\r\n\r\n"
    socket.flush
    socket.write "GET /second HTTP/1.1\r\nConnection: close\r\n\r\n"
    socket.flush
    response = socket.read
    socket.close
    
    wait_for_requests_to_complete!
    
    response.should include('/first-1', '/second-2')
  end
  
  it "should not pipeline request by default on HTTP 1.0" do
    socket = TCPSocket.new('0.0.0.0', 3333)
    socket.write "GET /first HTTP/1.0\r\n\r\n"
    socket.flush
    socket.write "GET /second HTTP/1.0\r\nConnection: close\r\n\r\n"
    response = socket.read
    socket.close
    
    wait_for_requests_to_complete!
    
    response.should include('/first-1')
    response.should_not include('/second-2')
  end
  
  it "should not pipeline request on same socket when connection is closed" do
    socket = TCPSocket.new('0.0.0.0', 3333)
    socket.write "GET /first HTTP/1.1\r\nConnection: close\r\n\r\n"
    socket.flush
    socket.write "GET /second HTTP/1.1\r\nConnection: close\r\n\r\n"
    response = socket.read
    socket.close
    
    wait_for_requests_to_complete!
    
    response.should include('/first-1')
    response.should_not include('/second-2')
  end
  
  it "should not allow more persistent connection then maximum" do
    @server.maximum_persistent_connections = 1
    
    socket1 = TCPSocket.new('0.0.0.0', 3333)
    socket1.write "GET / HTTP/1.1\r\n\r\n"
    socket1.flush
    socket2 = TCPSocket.new('0.0.0.0', 3333)    
    socket2.write "GET / HTTP/1.1\r\n\r\n"
    socket2.flush
    
    @server.backend.persistent_connection_count.should == 1
    @server.backend.size.should == 2
    
    socket1.close    
    socket2.close
  end
  
  it "should decrement persistent connection on close" do
    socket = TCPSocket.new('0.0.0.0', 3333)
    socket.write "GET / HTTP/1.1\r\n\r\n"
    socket.flush
    
    @server.backend.persistent_connection_count.should == 1
    
    socket.write "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
    socket.close
    
    wait_for_requests_to_complete!
    
    @server.backend.persistent_connection_count.should == 0
  end
  
  after do
    stop_server
  end
  
  private
    def wait_for_requests_to_complete!
      sleep 0.1 until @server.backend.size == 0
    end
end