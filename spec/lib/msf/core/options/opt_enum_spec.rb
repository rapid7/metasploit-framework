# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptEnum do

  it_behaves_like "an option", [], [], 'enum'

  subject do
    Msf::OptEnum.new('name',[true, 'A Boolean Value', 'Foo', ['Foo', 'Bar', 'Baz']])
  end

  context 'the validator' do
    it 'should return false for a value not in the list' do
      subject.valid?('Snap').should == false
    end

    it 'should return true for a value in the list' do
      subject.valid?('Bar').should == true
    end
  end
end