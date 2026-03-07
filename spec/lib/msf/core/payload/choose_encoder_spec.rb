require 'spec_helper'

RSpec.describe Msf::Payload, '.choose_encoder' do
  let(:framework) { instance_double(Msf::Framework) }
  let(:payloads) { instance_double(Msf::PayloadSet) }
  let(:payload) { instance_double(Msf::Payload) }
  let(:mod) { instance_double(Msf::Exploit) }
  let(:datastore) { Msf::DataStore.new }

  before(:each) do
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:datastore).and_return(datastore)
    allow(framework).to receive(:payloads).and_return(payloads)
    allow(payloads).to receive(:create).and_return(payload)
    allow(payload).to receive(:datastore).and_return(Msf::DataStore.new)
  end

  # --- Preferred encoder selection ---

  context 'with an x86 payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'windows/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_X86])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/x86/fnstenv_mov', nil],
        ['encoder/x86/call4_dword_xor', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'prefers x86/shikata_ga_nai' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/x86/shikata_ga_nai')
    end

    it 'configures the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/x86/shikata_ga_nai')
    end
  end

  context 'with an x64 payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_X64])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/x64/xor', nil],
        ['encoder/x64/xor_dynamic', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'prefers x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/x64/zutto_dekiru')
    end

    it 'configures the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/x64/zutto_dekiru')
    end
  end

  context 'with a cmd payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'cmd/unix/reverse_bash' })
      allow(payload).to receive(:arch).and_return([ARCH_CMD])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/cmd/base64', nil],
        ['encoder/cmd/echo', nil],
        ['encoder/cmd/generic_sh', nil],
        ['encoder/cmd/perl', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'prefers cmd/base64' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/cmd/base64')
    end

    it 'configures the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/cmd/base64')
    end
  end

  # --- Fallback to first compatible encoder ---

  context 'with a PHP payload (no preferred match)' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'php/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PHP])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/php/base64', nil],
        ['encoder/php/hex', nil],
        ['encoder/php/minify', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'falls back to the first compatible encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/php/base64')
    end

    it 'configures the datastore on fallback' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/php/base64')
    end
  end

  context 'with a ruby payload (no preferred match)' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'ruby/shell_reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_RUBY])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/ruby/base64', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'falls back to the first compatible encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/ruby/base64')
    end

    it 'configures the datastore on fallback' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/ruby/base64')
    end
  end

  context 'with a python payload (only generic/none)' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'python/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PYTHON])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/generic/none', nil],
      ])
    end

    it 'returns generic/none' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/generic/none')
    end

    it 'configures the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/generic/none')
    end
  end

  context 'with a mipsle payload (no preferred match)' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'linux/mipsle/shell/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_MIPSLE])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/mipsle/byte_xori', nil],
        ['encoder/mipsle/longxor', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'falls back to the first compatible encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/mipsle/byte_xori')
    end

    it 'configures the datastore on fallback' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/mipsle/byte_xori')
    end
  end

  # --- Single encoder ---

  context 'with a single compatible encoder' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'ruby/shell_reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_RUBY])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/ruby/base64', nil],
      ])
    end

    it 'returns the only available encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/ruby/base64')
    end

    it 'configures the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/ruby/base64')
    end
  end

  # --- Edge cases ---

  context 'with no payload set' do
    before(:each) do
      allow(payloads).to receive(:create).and_return(nil)
    end

    it 'returns nil' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to be_nil
    end
  end

  context 'with no compatible encoders' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'php/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PHP])
      allow(payload).to receive(:compatible_encoders).and_return([])
    end

    it 'returns nil' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to be_nil
    end

    it 'does not modify the datastore' do
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to be_nil
    end
  end

  # --- Datastore persistence across payload changes ---

  context 'when switching from x64 to PHP payload' do
    it 'updates the datastore with the new encoder' do
      # First: x64 payload selects zutto_dekiru
      datastore.import_options_from_hash({ 'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_X64])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/generic/none', nil],
      ])
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/x64/zutto_dekiru')

      # Second: switch to PHP payload
      datastore.import_options_from_hash({ 'PAYLOAD' => 'php/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PHP])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/php/base64', nil],
        ['encoder/php/minify', nil],
        ['encoder/generic/none', nil],
      ])
      described_class.choose_encoder(mod)
      expect(datastore['ENCODER']).to eq('encoder/php/base64')
    end
  end
end
