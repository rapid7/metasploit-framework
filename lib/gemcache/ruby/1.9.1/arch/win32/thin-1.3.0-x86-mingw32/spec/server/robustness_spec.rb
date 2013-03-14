require File.dirname(__FILE__) + '/../spec_helper'

describe Server, 'robustness' do
  before do
    start_server do |env|
      body = 'hello!'
      [200, { 'Content-Type' => 'text/html' }, body]
    end
  end
  
  it "should not crash when header too large" do
    100.times do
      begin
        socket = TCPSocket.new(DEFAULT_TEST_ADDRESS, DEFAULT_TEST_PORT)
        socket.write("GET / HTTP/1.1\r\n")
        socket.write("Host: localhost\r\n")
        socket.write("Connection: close\r\n")
        10000.times do
        	socket.write("X-Foo: #{'x' * 100}\r\n")
        	socket.flush
        end
        socket.write("\r\n")
        socket.read
        socket.close
      rescue Errno::EPIPE, Errno::ECONNRESET
				# Ignore.
			end
    end
  end
  
  after do
    stop_server
  end
end