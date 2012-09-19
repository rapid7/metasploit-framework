require File.dirname(__FILE__) + '/spec_helper'

describe Headers do
  before do
    @headers = Headers.new
  end
  
  it 'should allow duplicate on some fields' do
    @headers['Set-Cookie'] = 'twice'
    @headers['Set-Cookie'] = 'is cooler the once'
    
    @headers.to_s.should == "Set-Cookie: twice\r\nSet-Cookie: is cooler the once\r\n"
  end
  
  it 'should overwrite value on non duplicate fields' do
    @headers['Host'] = 'this is unique'
    @headers['Host'] = 'so is this'

    @headers.to_s.should == "Host: this is unique\r\n"
  end
  
  it 'should output to string' do
    @headers['Host'] = 'localhost:3000'
    @headers['Set-Cookie'] = 'twice'
    @headers['Set-Cookie'] = 'is cooler the once'
    
    @headers.to_s.should == "Host: localhost:3000\r\nSet-Cookie: twice\r\nSet-Cookie: is cooler the once\r\n"
  end

  it 'should ignore nil values' do
    @headers['Something'] = nil
    @headers.to_s.should_not include('Something: ')
  end

  it 'should format Time values correctly' do
    time = Time.now
    @headers['Modified-At'] = time
    @headers.to_s.should include("Modified-At: #{time.httpdate}")
  end
end