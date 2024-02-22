# -*- coding:binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::OptionGroup do
  subject { described_class.new(name: 'name', description: 'description') }

  describe '#add_option' do
    let(:option_name) { 'option_name' }
    context 'when the option group is empty' do
      it 'adds the option' do
        subject.add_option(option_name)
        expect(subject.option_names.length).to eql(1)
        expect(subject.option_names).to include(option_name)
      end
    end

    context 'when the option group contains options' do
      subject { described_class.new(name: 'name', description: 'description', option_names: ['existing_option']) }

      it 'adds the option' do
        subject.add_option(option_name)
        expect(subject.option_names.length).to eql(2)
        expect(subject.option_names).to include(option_name)
      end
    end
  end

  describe '#add_options' do
    let(:option_names) { %w[option_name1 option_name2] }
    context 'when the option group is empty' do
      it 'adds the option' do
        subject.add_options(option_names)
        expect(subject.option_names.length).to eql(2)
        expect(subject.option_names).to include(*option_names)
      end
    end

    context 'when the option group contains options' do
      subject { described_class.new(name: 'name', description: 'description', option_names: ['existing_option']) }

      it 'adds the option' do
        subject.add_options(option_names)
        expect(subject.option_names.length).to eql(3)
        expect(subject.option_names).to include(*option_names)
      end
    end
  end
end
