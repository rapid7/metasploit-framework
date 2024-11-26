# -*- coding:binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.shared_examples_for Msf::OptionalSession do
  include_context 'Msf::Simple::Framework'

  let(:options) { instance_double(Msf::OptionContainer) }
  let(:datastore) { instance_double(Msf::DataStoreWithFallbacks) }
  let(:session) { instance_double(Msf::Sessions::SMB) }
  let(:session_group) { instance_double(Msf::OptionGroup) }
  let(:rhost_group) { instance_double(Msf::OptionGroup) }
  let(:groups) do
    {
      'SESSION' => session_group,
      'RHOST' => rhost_group
    }
  end
  describe '#validate' do
    before(:each) do
      allow(options).to receive(:validate)
      allow(options).to receive(:[]).and_return(instance_double(Msf::OptBase))
      allow(options).to receive(:groups).and_return(groups)
      allow(mod).to receive(:options).and_return(options)
      allow(mod).to receive(:datastore).and_return(datastore)
      allow(mod).to receive(:framework).and_return(framework)
      allow(session_group).to receive(:validate)
      allow(rhost_group).to receive(:validate)
    end

    context 'when neither SESSION or RHOST are set' do
      before(:each) do
        allow(mod).to receive(:rhost).and_return(nil)
        allow(mod).to receive(:session).and_return(nil)
      end

      it 'raises an error' do
        expect { mod.validate }.to raise_error(Msf::OptionValidateError).with_message('A SESSION or RHOST must be provided')
      end
    end

    context 'when both SESSION and RHOST are set' do
      before(:each) do
        allow(datastore).to receive(:[]).with('SESSION').and_return('SESSION_ID')
        allow(datastore).to receive(:[]).with('RHOST').and_return('RHOST_VALUE')
        allow(mod).to receive(:session).and_return(session)
        allow(mod).to receive(:rhost).and_return('RHOST_VALUE')
      end

      it 'validates the SESSION only' do
        mod.validate
        expect(session_group).to have_received(:validate).once
        expect(rhost_group).not_to have_received(:validate)
      end
    end

    context 'when only RHOST is set' do
      before(:each) do
        allow(datastore).to receive(:[]).with('RHOST').and_return('RHOST_VALUE')
        allow(datastore).to receive(:[]).with('SESSION').and_return(nil)
        allow(mod).to receive(:rhost).and_return('RHOST_VALUE')
        allow(mod).to receive(:session).and_return(nil)
      end

      it 'only validates the RHOST group' do
        mod.validate
        expect(rhost_group).to have_received(:validate).once
        expect(session_group).not_to have_received(:validate)
      end
    end

    context 'when only SESSION is set' do
      before(:each) do
        allow(datastore).to receive(:[]).with('SESSION').and_return('SESSION_ID')
        allow(datastore).to receive(:[]).with('RHOST').and_return(nil)
        allow(mod).to receive(:session).and_return(session)
        allow(mod).to receive(:rhost).and_return(nil)
      end

      it 'validates the SESSION only' do
        mod.validate
        expect(session_group).to have_received(:validate).once
        expect(rhost_group).not_to have_received(:validate)
      end

      context 'when the session is not the correct type' do
        before(:each) do
          allow(mod).to receive(:session_types).and_return(['correct_session_type'])
          allow(session).to receive(:type).and_return('wrong_session_type')
        end

        it 'should raise an error about the wrong session type' do
          expect { mod.validate }.to raise_error(Msf::OptionValidateError) { |error| expect(error.options).to eq ['SESSION'] }
        end
      end

      context 'when the session is the correct type' do
        before(:each) do
          allow(mod).to receive(:session_types).and_return(['correct_session_type'])
          allow(session).to receive(:type).and_return('correct_session_type')
        end

        it 'should raise an error about the wrong session type' do
          expect { mod.validate }.not_to raise_error
        end
      end
    end
  end
end
