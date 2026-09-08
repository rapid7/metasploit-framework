# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Ui::Console::ModuleOptionValidation do
  subject(:validator) do
    validator = validator_class.new
    validator.framework = framework
    validator
  end

  let(:validator_class) do
    Class.new do
      include Msf::Ui::Console::ModuleOptionValidation

      attr_accessor :framework
    end
  end

  let(:framework) do
    instance_double(Msf::Framework, datastore: Msf::DataStore.new)
  end

  let(:mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      def initialize
        super

        register_options(
          [
            Msf::OptString.new('MODE', [false, 'Mode', 'visible']),
            Msf::OptString.new('ALWAYS_VISIBLE', [false, 'Always visible', nil], aliases: ['OLD_ALWAYS_VISIBLE']),
            Msf::OptString.new(
              'CONDITIONAL',
              [false, 'Conditional option', nil],
              aliases: ['OLD_CONDITIONAL'],
              conditions: %w[MODE == visible]
            )
          ]
        )
      end
    end

    mod_klass.new
  end

  describe '#valid_datastore_option_names' do
    context 'when a conditional option is visible' do
      it 'includes the option and its aliases' do
        option_names = validator.valid_datastore_option_names(mod, include_aliases: true)

        expect(option_names).to include('CONDITIONAL')
        expect(option_names).to include('OLD_CONDITIONAL')
      end
    end

    context 'when a conditional option is hidden' do
      before do
        mod.datastore['MODE'] = 'hidden'
      end

      it 'includes the option and its aliases by default' do
        option_names = validator.valid_datastore_option_names(mod, include_aliases: true)

        expect(option_names).to include('CONDITIONAL')
        expect(option_names).to include('OLD_CONDITIONAL')
      end

      it 'excludes the option and its aliases when only active options are requested' do
        option_names = validator.valid_datastore_option_names(mod, include_aliases: true, active_only: true)

        expect(option_names).to include('MODE')
        expect(option_names).to include('ALWAYS_VISIBLE')
        expect(option_names).to include('OLD_ALWAYS_VISIBLE')
        expect(option_names).not_to include('CONDITIONAL')
        expect(option_names).not_to include('OLD_CONDITIONAL')
      end

      it 'does not report the option as unknown' do
        message = validator.unknown_datastore_option_message(mod, 'CONDITIONAL')

        expect(message).to be_nil
      end
    end
  end
end
