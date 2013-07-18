# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'


describe Msf::OptAddress do
  subject{ Msf::OptAddress.new('RHOST', [true, 'The target address', '']) }

  it 'should return a type of address' do
    subject.type.should == 'address'
  end

  context 'the validator' do
    it 'should return true for a valid ipv4 address' do
      subject.valid?('192.168.1.1').should == true
    end

    it 'should return true for a valid ipv6 address' do
      subject.valid?('2607:f0d0:1002:0051:0000:0000:0000:0004').should == true
    end

    it 'should return true for a valid compressed ipv6 address' do
      subject.valid?('2607:f0d0:1002:51::4').should == true
    end

    it 'should return false for nil' do
      subject.valid?(nil).should == false
    end

    it 'should return false for an empty string' do
      subject.valid?('').should == false
    end

    it 'should return false for an incomplete ip4 address' do
      subject.valid?('192.168.1').should == false
    end

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