# -*- coding:binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Module::Options do
  subject(:mod) do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  describe '#register_option_group' do
    let(:name) { 'name' }
    let(:description) { 'description' }
    let(:option_names) { %w[option1 option2] }

    context 'there are no registered option groups' do
      it 'registers a new option group' do
        subject.send(:register_option_group, name: name, description: description, option_names: option_names)
        expect(subject.options.groups.length).to eq(1)
        expect(subject.options.groups.keys).to include(name)
      end
    end

    context 'there is a registered option group' do
      let(:existing_name) { 'existing_name' }
      let(:existing_options) { ['existing_option_names'] }
      let(:existing_description) { 'existing_description' }
      before(:each) do
        subject.send(:register_option_group, name: existing_name, description: existing_description, option_names: existing_options)
      end

      it 'registers a an additional option group' do
        subject.send(:register_option_group, name: name, description: description, option_names: option_names)
        expect(subject.options.groups.length).to eq(2)
        expect(subject.options.groups.keys).to include(name, existing_name)
      end

      context 'when adding a group with the same name' do
        it 'merges the option groups together' do
          subject.send(:register_option_group, name: existing_name, description: description, option_names: option_names)
          expect(subject.options.groups.length).to eq(1)
          expect(subject.options.groups.keys).to include(existing_name)
          expect(subject.options.groups[existing_name].option_names).to include(*existing_options, *option_names)
          expect(subject.options.groups[existing_name].description).to eq(description)
        end

        it 'overwrites the existing option group' do
          subject.send(:register_option_group, name: existing_name, description: description, option_names: option_names, merge: false)
          expect(subject.options.groups.length).to eq(1)
          expect(subject.options.groups.keys).to include(existing_name)
          expect(subject.options.groups[existing_name].option_names).to include(*option_names)
          expect(subject.options.groups[existing_name].description).to eq(description)
        end
      end
    end
  end
end
