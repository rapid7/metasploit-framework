require File.dirname(__FILE__) + '/../spec_helper'

describe Request, 'persistent' do
  before do
    @request = Request.new
  end
  
  it "should not assume that a persistent connection is maintained for HTTP version 1.0" do
    @request.env['HTTP_VERSION'] = 'HTTP/1.0'
    @request.should_not be_persistent
  end

  it "should assume that a persistent connection is maintained for HTTP version 1.0 when specified" do
    @request.env['HTTP_VERSION'] = 'HTTP/1.0'
    @request.env['HTTP_CONNECTION'] = 'Keep-Alive'
    @request.should be_persistent
  end
  
  it "should maintain a persistent connection for HTTP/1.1 client" do
    @request.env['HTTP_VERSION'] = 'HTTP/1.1'
    @request.env['HTTP_CONNECTION'] = 'Keep-Alive'
    @request.should be_persistent
  end

  it "should maintain a persistent connection for HTTP/1.1 client by default" do
    @request.env['HTTP_VERSION'] = 'HTTP/1.1'
    @request.should be_persistent
  end

  it "should not maintain a persistent connection for HTTP/1.1 client when Connection header include close" do
    @request.env['HTTP_VERSION'] = 'HTTP/1.1'
    @request.env['HTTP_CONNECTION'] = 'close'
    @request.should_not be_persistent
  end
end