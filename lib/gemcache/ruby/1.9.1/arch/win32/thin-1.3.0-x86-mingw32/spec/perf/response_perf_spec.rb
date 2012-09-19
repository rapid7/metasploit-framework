require File.dirname(__FILE__) + '/../spec_helper'

describe Response, 'performance' do
  before do
    @response = Response.new
    @response.body = ''
  end
  
  it "should be fast" do
    @response.body << <<-EOS
<html><head><title>Dir listing</title></head>
<body><h1>Listing stuff</h1><ul>
#{'<li>Hi!</li>' * 100}
</ul></body></html>
EOS

    proc { @response.each { |l| l } }.should be_faster_then(0.00011)
  end
end