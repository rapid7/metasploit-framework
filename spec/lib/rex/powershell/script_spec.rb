# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

RSpec.describe Rex::Powershell::Output do

  let(:example_script) do
    Rex::Text.rand_text_alpha(400)
  end

  let(:subject) do
    Rex::Powershell::Script.new(example_script)
  end

  describe "::initialize" do
    it 'should create a new script object' do
      expect(subject).to be
      expect(subject).to be_kind_of Rex::Powershell::Script
      expect(subject.rig).to be
      expect(subject.rig).to be_kind_of Rex::RandomIdentifierGenerator
      expect(subject.code).to be
      expect(subject.code).to be_kind_of String
      expect(subject.code.empty?).to be_falsey
      expect(subject.functions.empty?).to be_truthy
    end
  end

  describe "::to_byte_array" do
    it 'should generate a powershell byte array' do
      byte_array = Rex::Powershell::Script.to_byte_array("parp")
      expect(byte_array).to be
      expect(byte_array).to be_kind_of String
      expect(byte_array.include?('[Byte[]] $')).to be_truthy
    end
  end

  describe "::code_modifiers" do
    it 'should return an array of modifier methods' do
      mods = Rex::Powershell::Script.code_modifiers
      expect(mods).to be
      expect(mods).to be_kind_of Array
      expect(mods.empty?).to be_falsey
    end
  end

end

