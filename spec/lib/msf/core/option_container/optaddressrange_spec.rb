# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptAddressRange do
  subject{ Msf::OptAddressRange.new('RHOSTS', [true, 'The target addresses', '']) }
  let(:address_range_file_path) { File.expand_path('short_address_list.txt',FILE_FIXTURES_PATH)}

  it 'should return a type of addressrange' do
    subject.type.should == 'addressrange'
  end

  context 'the normalizer' do
    it 'should handle a call for random IPs' do
      random_addresses = subject.normalize('rand:5')
      random_addresses.kind_of?(String).should == true
      ips = random_addresses.split(' ')
      ips.count.should == 5
      ips.each do |ip|
        (ip =~ Rex::Socket::MATCH_IPV4).should == 0
      end
    end

    it ' should handle a file directive' do
      address_string = subject.normalize("file:#{address_range_file_path}")
      address_string.kind_of?(String).should == true
      ips = address_string.split(' ')
      ips.count.should == 5
      ips.each do |ip|
        (ip =~ Rex::Socket::MATCH_IPV4).should == 0
      end
    end

    it 'should return the supplied value for a regular address range' do
      range = '192.168.1.0/24'
      subject.normalize(range).should == range
    end

    it 'should return nil for a non string input' do
      subject.normalize(true).should     == nil
      subject.normalize(50).should       == nil
      subject.normalize([]).should       == nil
      subject.normalize([1,2]).should    == nil
      subject.normalize({}).should       == nil
      subject.normalize({:foo => 'bar'}) == nil
    end
  end

  context 'the validator' do
    it 'should return false for a non-string value' do
      subject.valid?(true).should     == false
      subject.valid?(50).should       == false
      subject.valid?([]).should       == false
      subject.valid?([1,2]).should    == false
      subject.valid?({}).should       == false
      subject.valid?({:foo => 'bar'}) == false
    end

  end


end