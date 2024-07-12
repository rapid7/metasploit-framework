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

  describe '#validate' do
    let(:required_option_name) { 'required_name' }
    let(:option_names) { ['not_required_name', required_option_name] }
    let(:required_names) { [required_option_name] }
    let(:options) { instance_double(Msf::OptionContainer) }
    let(:datastore) { instance_double(Msf::DataStoreWithFallbacks) }

    context 'when there are no required options' do
      subject { described_class.new(name: 'name', description: 'description', option_names: option_names) }

      context 'when no values are set for the options' do

        before(:each) do
          allow(options).to receive(:[]).and_return(instance_double(Msf::OptBase))
          allow(datastore).to receive(:[]).and_return(nil)
        end

        it 'validates the options in the group' do
          expect { subject.validate(options, datastore) }.not_to raise_error
        end
      end

      context 'when values are set for the options' do

        before(:each) do
          allow(options).to receive(:[]).and_return(instance_double(Msf::OptBase))
          allow(datastore).to receive(:[]).and_return('OptionValue')
        end

        it 'validates the options in the group' do
          expect { subject.validate(options, datastore) }.not_to raise_error
        end
      end

      context 'when the options have not been registered' do

        before(:each) do
          allow(options).to receive(:[]).and_return(nil)
        end

        it 'does not attempt to validate the options' do
          expect { subject.validate(options, datastore) }.not_to raise_error
        end
      end
    end

    context 'when there is a required option' do
      subject { described_class.new(name: 'name', description: 'description', option_names: option_names, required_options: required_names) }
      let(:error_message) { "The following options failed to validate: #{required_option_name}." }

      context 'when no values are set for the options' do

        before(:each) do
          allow(options).to receive(:[]).and_return(instance_double(Msf::OptBase))
          allow(datastore).to receive(:[]).and_return(nil)
        end

        it 'raises an error only for the required option' do
          expect { subject.validate(options, datastore) }.to raise_error(Msf::OptionValidateError).with_message(error_message)
        end
      end

      context 'when values are set for the options' do

        before(:each) do
          allow(options).to receive(:[]).and_return(instance_double(Msf::OptBase))
          allow(datastore).to receive(:[]).and_return('OptionValue')
        end

        it 'validates the options in the group' do
          expect { subject.validate(options, datastore) }.not_to raise_error
        end
      end

      context 'when the options have not been registered' do

        before(:each) do
          allow(options).to receive(:[]).and_return(nil)
        end

        it 'does not attempt to validate the options' do
          expect { subject.validate(options, datastore) }.not_to raise_error
        end
      end
    end

  end
end
