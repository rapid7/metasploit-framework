# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

describe Rex::Powershell::Output do

  let(:example_script) do
    Rex::Text.rand_text_alpha(400)
  end

  let(:subject) do
    Rex::Powershell::Script.new(example_script)
  end

  describe "::initialize" do
    it 'should create a new script object' do
      subject.should be
      subject.should be_kind_of Rex::Powershell::Script
      subject.rig.should be
      subject.rig.should be_kind_of Rex::RandomIdentifierGenerator
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.empty?.should be_falsey
      subject.functions.empty?.should be_truthy
    end
  end

  describe "::to_byte_array" do
    it 'should generate a powershell byte array' do
      byte_array = Rex::Powershell::Script.to_byte_array("parp")
      byte_array.should be
      byte_array.should be_kind_of String
      byte_array.include?('[Byte[]] $').should be_truthy
    end
  end

  describe "::code_modifiers" do
    it 'should return an array of modifier methods' do
      mods = Rex::Powershell::Script.code_modifiers
      mods.should be
      mods.should be_kind_of Array
      mods.empty?.should be_falsey
    end
  end

end

