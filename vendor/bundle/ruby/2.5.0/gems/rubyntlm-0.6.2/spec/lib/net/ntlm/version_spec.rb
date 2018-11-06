require 'spec_helper'
require File.expand_path("#{File.dirname(__FILE__)}/../../../../lib/net/ntlm/version")

describe Net::NTLM::VERSION do

  it 'should contain an integer value for Major Version' do
    expect(Net::NTLM::VERSION::MAJOR).to be_an Integer
  end

  it 'should contain an integer value for Minor Version' do
    expect(Net::NTLM::VERSION::MINOR).to be_an Integer
  end

  it 'should contain an integer value for Patch Version' do
    expect(Net::NTLM::VERSION::TINY).to be_an Integer
  end

  it 'should contain an aggregate version string' do
    string = [
        Net::NTLM::VERSION::MAJOR,
        Net::NTLM::VERSION::MINOR,
        Net::NTLM::VERSION::TINY
    ].join('.')
    expect(Net::NTLM::VERSION::STRING).to be_a String
    expect(Net::NTLM::VERSION::STRING).to eq(string)
  end
end
