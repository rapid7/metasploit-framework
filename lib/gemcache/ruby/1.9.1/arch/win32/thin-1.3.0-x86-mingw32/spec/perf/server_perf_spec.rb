require File.dirname(__FILE__) + '/../spec_helper'

describe Server, 'performance' do
  before do
    start_server do |env|
      body = env.inspect + env['rack.input'].read
      [200, { 'Content-Length' => body.size.to_s }, body]
    end
  end
  
  it "should handle GET in less then #{get_request_time = 0.0045} RubySecond" do
    proc { get('/') }.should be_faster_then(get_request_time)
  end
  
  it "should handle POST in less then #{post_request_time = 0.007} RubySecond" do
    proc { post('/', :file => 'X' * 1000) }.should be_faster_then(post_request_time)
  end
  
  after do
    stop_server
  end
end

describe Server, 'UNIX socket performance' do
  before do
    start_server('/tmp/thin_test.sock') do |env|
      body = env.inspect + env['rack.input'].read
      [200, { 'Content-Length' => body.size.to_s }, body]
    end
  end
  
  it "should handle GET in less then #{get_request_time = 0.002} RubySecond" do
    proc { get('/') }.should be_faster_then(get_request_time)
  end
  
  after do
    stop_server
  end
end