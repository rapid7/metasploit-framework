# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptEnum do
  it_behaves_like 'an option', [], [], 'enum'

  let(:required_optenum) { Msf::OptEnum.new('name', [true, 'A Boolean Value', 'Foo', ['Foo', 'Bar', 'Baz']]) }
  let(:not_required_optenum) { Msf::OptEnum.new('name', [false, 'A Boolean Value', 'Foo', ['Foo', 'Bar', 'Baz']]) }

  context 'the validator when required' do
    it 'should return false for a value not in the list' do
      expect(required_optenum.valid?('Snap')).to eq false
    end

    it 'should return true for a value in the list' do
      expect(required_optenum.valid?('Bar')).to eq true
    end

    it 'should return true for a value in the list with alternative casing' do
      expect(required_optenum.valid?('bar')).to eq true
    end

    it 'should return false for a nil value' do
      expect(required_optenum.valid?(nil)).to eq false
    end
  end

  context 'the validator when not required' do
    it 'should return true for a nil value' do
      expect(not_required_optenum.valid?(nil)).to eq true
    end

    it 'should return true for a value in the list' do
      expect(not_required_optenum.valid?('Bar')).to eq true
    end

    it 'should return true for a value in the list with alternative casing' do
      expect(not_required_optenum.valid?('bar')).to eq true
    end

    it 'should return false for a value not in the list' do
      expect(not_required_optenum.valid?('Snap')).to eq false
    end
  end

  context 'normalize when required' do
    it 'should return nil for a nil value' do
      expect(required_optenum.normalize(nil)).to eq nil
    end

    it 'should return the value string for a value in the list' do
      expect(required_optenum.normalize('Bar')).to eq 'Bar'
    end

    it 'should return the value string for a value with alternative casing' do
      expect(required_optenum.normalize('bar')).to eq 'Bar'
    end

    it 'should return nil for a value not in the list' do
      expect(required_optenum.normalize('Snap')).to eq nil
    end
  end

  context 'normalize when not required' do
    it 'should return nil for a nil value' do
      expect(not_required_optenum.normalize(nil)).to eq nil
    end

    it 'should return the value string for a value in the list' do
      expect(not_required_optenum.normalize('Bar')).to eq 'Bar'
    end

    it 'should return the value string for a value with alternative casing' do
      expect(not_required_optenum.normalize('bar')).to eq 'Bar'
    end

    it 'should return nil for a value not in the list' do
      expect(not_required_optenum.normalize('Snap')).to eq nil
    end
  end
end
