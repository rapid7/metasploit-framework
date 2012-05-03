require File.dirname(__FILE__) + '/spec_helper'

describe Response do
  before do
    @response = Response.new
    @response.headers['Content-Type'] = 'text/html'
    @response.headers['Content-Length'] = '0'
    @response.body = ''
  end
  
  it 'should output headers' do
    @response.headers_output.should include("Content-Type: text/html", "Content-Length: 0", "Connection: close")
  end
  
  it 'should include server name header' do
    @response.headers_output.should include("Server: thin")
  end
  
  it 'should output head' do
    @response.head.should include("HTTP/1.1 200 OK", "Content-Type: text/html", "Content-Length: 0",
                                  "Connection: close", "\r\n\r\n")
  end
  
  it 'should allow duplicates in headers' do
    @response.headers['Set-Cookie'] = 'mium=7'
    @response.headers['Set-Cookie'] = 'hi=there'
    
    @response.head.should include("Set-Cookie: mium=7", "Set-Cookie: hi=there")
  end
  
  it 'should parse simple header values' do
    @response.headers = {
      'Host' => 'localhost'
    }
    
    @response.head.should include("Host: localhost")
  end
  
  it 'should parse multiline header values in several headers' do
    @response.headers = {
      'Set-Cookie' => "mium=7\nhi=there"
    }
    
    @response.head.should include("Set-Cookie: mium=7", "Set-Cookie: hi=there")
  end

  it 'should ignore nil headers' do
    @response.headers = nil
    @response.headers = { 'Host' => 'localhost' }
    @response.headers = { 'Set-Cookie' => nil }
    @response.head.should include('Host: localhost')
  end
  
  it 'should output body' do
    @response.body = ['<html>', '</html>']
    
    out = ''
    @response.each { |l| out << l }
    out.should include("\r\n\r\n<html></html>")
  end
    
  it 'should output String body' do
    @response.body = '<html></html>'
    
    out = ''
    @response.each { |l| out << l }
    out.should include("\r\n\r\n<html></html>")
  end
    
  it "should not be persistent by default" do
    @response.should_not be_persistent
  end
  
  it "should not be persistent when no Content-Length" do
    @response = Response.new
    @response.headers['Content-Type'] = 'text/html'
    @response.body = ''
    
    @response.persistent!
    @response.should_not be_persistent
  end
  
  it "should be persistent when the status code implies it should stay open" do
    @response = Response.new
    @response.status = 100
    # "There are no required headers for this class of status code" -- HTTP spec 10.1
    @response.body = ''

    # Specifying it as persistent in the code is NOT required
    # @response.persistent!
    @response.should be_persistent
  end
  
  it "should be persistent when specified" do
    @response.persistent!
    @response.should be_persistent
  end
  
  it "should be closeable" do
    @response.close
  end
end