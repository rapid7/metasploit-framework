require 'spec_helper'

describe Server, 'on TCP socket' do
  before do
    start_server do |env|
      body = env.inspect + env['rack.input'].read
      [200, { 'Content-Type' => 'text/html' }, body]
    end
  end
  
  it 'should GET from Net::HTTP' do
    get('/?cthis').should include('cthis')
  end
  
  it 'should GET from TCPSocket' do
    status, headers, body = parse_response(send_data("GET /?this HTTP/1.0\r\nConnection: close\r\n\r\n"))
    status.should == 200
    headers['Content-Type'].should == 'text/html'
    headers['Connection'].should == 'close'
    body.should include('this')
  end
  
  it 'should return empty string on incomplete headers' do
    send_data("GET /?this HTTP/1.1\r\nHost:").should be_empty
  end
  
  it 'should return empty string on incorrect Content-Length' do
    send_data("POST / HTTP/1.1\r\nContent-Length: 300\r\nConnection: close\r\n\r\naye").should be_empty
  end
  
  it 'should POST from Net::HTTP' do
    post('/', :arg => 'pirate').should include('arg=pirate')
  end
  
  it 'should handle big POST' do
    big = 'X' * (20 * 1024)
    post('/', :big => big).should include(big)
  end
  
  it "should retreive remote address" do
    get('/').should include('"REMOTE_ADDR"=>"127.0.0.1"')
  end
  
  after do
    stop_server
  end
end
