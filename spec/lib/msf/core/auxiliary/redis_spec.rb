require 'spec_helper'

RSpec.describe Msf::Auxiliary::Redis do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Redis)
    mod
  end

  describe '.parse_redis_response' do
    context "given a simple string" do
      it "returns that string" do
        expect(subject.parse_redis_response("+test")).to eql("test")
      end
    end

    context "given a bulk string" do
      it "returns that string" do
        expect(subject.parse_redis_response("$10\r\ntest\r\ntest\r\nother junk")).to eql("test\r\ntest")
      end
    end

    context "given an array" do
      it "correctly parses it" do
        expect(subject.parse_redis_response("*3\r\n$3\r\nOne\r\n+Two\r\n$5\r\nThree")).to eql(["One","Two","Three"])
      end
    end

    context "given a nested array" do
      it "correctly parses it" do
        expect(subject.parse_redis_response("*2\r\n$1\r\n0\r\n*1\r\n$4\r\ntest\r\njunk")).to eql(["0",["test"]])
      end
    end
  end
end
