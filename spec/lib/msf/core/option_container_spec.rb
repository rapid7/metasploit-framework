# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptionContainer do
  describe '#[]' do
    let(:mock_opt_class) do
      double('mock_opt_class', name: 'mock_opt_class', new: mock_opt_instance)
    end
    let(:mock_opt_instance) do
      double(
        'mock_opt_instance',
        name: 'option_name',
        'advanced=': nil,
        'evasion=': nil,
        'owner=': nil
      )
    end

    let(:subject) do
      described_class.new(
        {
          'option_name' => [mock_opt_class, true, nil, false]
        }
      )
    end

    it 'returns the option instance when it is present' do
      expect(subject['option_name']).to eq mock_opt_instance
    end

    it 'returns nil when the option is not present' do
      expect(subject['foo']).to be_nil
    end
  end

  describe '#validate' do
    context 'when an RHOSTS option is not present' do
      let(:options_with_rhosts) do
        described_class.new(
          [
            Msf::OptString.new('HttpUsername', required: true, default: nil),
            Msf::OptString.new('HttpPassword', required: true, default: nil),
            Msf::OptFloat.new('FloatValue', required: true, default: 2)
          ]
        )
      end

      it 'returns true when all options are valid' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['HttpUsername'] = 'user'
        datastore['HttpPassword'] = 'pass'
        expect(options_with_rhosts.validate(datastore)).to be true
      end

      it 'raises an error when required values are missing' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['HttpUsername'] = 'user'
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expect(error.options).to eq(['HttpPassword'])
          expect(error.reasons).to eq({})
        }
      end

      it 'has a side effect of normalizing values' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['HttpUsername'] = 'user'
        datastore['HttpPassword'] = 'pass'
        datastore.store('FloatValue', '2.0')
        expect(datastore['FloatValue']).to eq '2.0'
        expect(options_with_rhosts.validate(datastore)).to be true
        expect(datastore['FloatValue']).to eq 2.0
      end
    end

    context 'when an RHOSTS option is present' do
      let(:options_with_rhosts) do
        described_class.new(
          [
            Msf::OptRhosts.new('RHOSTS', required: true),
            Msf::OptString.new('HttpUsername', required: true, default: nil),
            Msf::OptString.new('HttpPassword', required: true, default: nil),
            Msf::OptFloat.new('FloatValue', required: true, default: 2)
          ]
        )
      end

      it 'returns true when all options are valid' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = '198.51.100.1'
        datastore['HttpUsername'] = 'user'
        datastore['HttpPassword'] = 'pass'
        expect(options_with_rhosts.validate(datastore)).to be true
      end

      it 'returns true when RHOST values set required options, i.e. missing required HttpUser/Pass options' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = 'http://foo:bar@198.51.100.1:8080'
        expect(options_with_rhosts.validate(datastore)).to be true
      end

      it 'raises an error when required values are missing' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = '198.51.100.1'
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expect(error.options).to eq(['HttpUsername', 'HttpPassword'])
          expect(error.reasons).to eq({})
        }
      end

      it 'raises an error when RHOSTS is blank' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = ''
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expect(error.options).to eq(['RHOSTS'])
          expect(error.reasons).to eq({})
        }
      end

      it 'raises an error when RHOST values do not set required values, i.e. missing required HttpUser/Pass options' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = 'http://198.51.100.1:8080'
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expect(error.options).to eq(['HttpUsername', 'HttpPassword'])
          expect(error.reasons).to eq({})
        }
      end

      it 'raises an error when some RHOST values do not set required values, i.e. missing required HttpUser/Pass options' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = 'http://user:pass@198.51.100.1:8080 http://user@198.51.100.1:8080 http://198.51.100.1:8081'
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expected_reasons = {
            'HttpPassword' => [
              'for rhosts value http://user@198.51.100.1:8080',
              'for rhosts value http://198.51.100.1:8081'
            ],
            'HttpUsername' => [
              'for rhosts value http://198.51.100.1:8081'
            ]
          }
          expect(error.options).to eq(['HttpPassword', 'HttpUsername'])
          expect(error.reasons).to eq(expected_reasons)
        }
      end

      it 'raises an error when RHOSTS values are invalid' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = 'http://198.51.100.1:8080path http://198.51.100.1:8080 http://foo:bar@198.51.100.1:8080path'
        expect { options_with_rhosts.validate(datastore) }.to raise_error(Msf::OptionValidateError) { |error|
          expected_reasons = {
            'RHOSTS' => [
              'unexpected values: http://198.51.100.1:8080path, http://foo:bar@198.51.100.1:8080path'
            ]
          }
          expect(error.options).to eq(['RHOSTS', 'HttpUsername', 'HttpPassword'])
          expect(error.reasons).to eq(expected_reasons)
        }
      end

      it 'has a side effect of normalizing values' do
        datastore = Msf::ModuleDataStore.new(nil)
        datastore.import_options(options_with_rhosts)
        datastore['RHOSTS'] = '127.0.0.1'
        datastore['HttpUsername'] = 'user'
        datastore['HttpPassword'] = 'pass'
        datastore.store('FloatValue', '2.0')
        expect(datastore['FloatValue']).to eq '2.0'
        expect(options_with_rhosts.validate(datastore)).to be true
        expect(datastore['FloatValue']).to eq 2.0
      end
    end
  end
end
