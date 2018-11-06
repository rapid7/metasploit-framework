require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::Base do

  subject { described_class.new(lambda {}) }

  describe "#random_string" do
    it "outputs a string of 32 characters" do
      subject.random_string.length.should == 32
    end
  end

  describe "#referrer" do
    it "Reads referrer from Referer header" do
      env = {"HTTP_HOST" => "foo.com", "HTTP_REFERER" => "http://bar.com/valid"}
      subject.referrer(env).should == "bar.com"
    end

    it "Reads referrer from Host header when Referer header is relative" do
      env = {"HTTP_HOST" => "foo.com", "HTTP_REFERER" => "/valid"}
      subject.referrer(env).should == "foo.com"
    end

    it "Reads referrer from Host header when Referer header is missing" do
      env = {"HTTP_HOST" => "foo.com"}
      subject.referrer(env).should == "foo.com"
    end

    it "Returns nil when Referer header is missing and allow_empty_referrer is false" do
      env = {"HTTP_HOST" => "foo.com"}
      subject.options[:allow_empty_referrer] = false
      subject.referrer(env).should be_nil
    end

    it "Returns nil when Referer header is invalid" do
      env = {"HTTP_HOST" => "foo.com", "HTTP_REFERER" => "http://bar.com/bad|uri"}
      subject.referrer(env).should be_nil
    end
  end
end
