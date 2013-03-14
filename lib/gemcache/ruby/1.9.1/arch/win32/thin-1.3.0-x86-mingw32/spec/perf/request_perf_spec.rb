require File.dirname(__FILE__) + '/../spec_helper'

describe Request, 'performance' do
  it "should be faster then #{max_parsing_time = 0.0002} RubySeconds" do
    body = <<-EOS.chomp.gsub("\n", "\r\n")
POST /postit HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Content-Type: text/html
Content-Length: 37

hi=there&name=marc&email=macournoyer@gmail.com
EOS

    proc { R(body) }.should be_faster_then(max_parsing_time)
  end

  it 'should be comparable to Mongrel parser' do
    require 'http11'

    body = <<-EOS.chomp.gsub("\n", "\r\n")
POST /postit HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Content-Type: text/html
Content-Length: 37

hi=there&name=marc&email=macournoyer@gmail.com
EOS

    tests = 10_000
    puts
    Benchmark.bmbm(10) do |results|
      results.report("mongrel:") { tests.times { Mongrel::HttpParser.new.execute({}, body.dup, 0) } }
      results.report("thin:") { tests.times { Thin::HttpParser.new.execute({'rack.input' => StringIO.new}, body.dup, 0) } }
    end
  end if ENV['BM']
end