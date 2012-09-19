require File.dirname(__FILE__) + '/../spec_helper'

describe Server, 'with threads' do
  before do
    @requests = 0
    start_server DEFAULT_TEST_ADDRESS, DEFAULT_TEST_PORT, :threaded => true do |env|
      sleep env['PATH_INFO'].delete('/').to_i
      @requests += 1
      [200, { 'Content-Type' => 'text/html' }, 'hi']
    end
  end
  
  it "should process request" do
    get('/').should_not be_empty
  end
  
  it "should process requests when blocked" do
    slow_request = Thread.new { get('/3') }
    get('/').should_not be_empty
    @requests.should == 1
    slow_request.kill
  end
  
  after do
    stop_server
  end
end