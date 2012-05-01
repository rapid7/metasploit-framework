require File.dirname(__FILE__) + '/../spec_helper'
require 'digest/sha1'

describe Request, 'legacy Mongrel tests' do
  it 'should raise error on large header names' do
    proc { R("GET /#{rand_data(10,120)} HTTP/1.1\r\nX-#{rand_data(1024, 1024+(1024))}: Test\r\n\r\n") }.
      should raise_error(InvalidRequest)
  end

  it 'should raise error on large mangled field values' do
    proc { R("GET /#{rand_data(10,120)} HTTP/1.1\r\nX-Test: #{rand_data(1024, 1024*1024, false)}\r\n\r\n") }.
      should raise_error(InvalidRequest)
  end
  
  it 'should raise error on big fat ugly headers' do
    get = "GET /#{rand_data(10,120)} HTTP/1.1\r\n"
    get << "X-Test: test\r\n" * (80 * 1024)
    proc { R(get) }.should raise_error(InvalidRequest)
  end

  it 'should raise error on random garbage' do
    proc { R("GET #{rand_data(1024, 1024+(1024), false)} #{rand_data(1024, 1024+(1024), false)}\r\n\r\n") }.
      should raise_error(InvalidRequest)
  end
  
  private
    def rand_data(min, max, readable=true)
      count = min + ((rand(max)+1) *10).to_i
      res = count.to_s + "/"

      if readable
        res << Digest::SHA1.hexdigest(rand(count * 100).to_s) * (count / 40)
      else
        res << Digest::SHA1.digest(rand(count * 100).to_s) * (count / 20)
      end

      return res
    end
end