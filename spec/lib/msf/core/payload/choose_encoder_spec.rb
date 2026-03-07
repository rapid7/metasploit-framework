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

  # --- Architecture filtering ---

  context 'with a PHP payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'php/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PHP])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/php/base64', nil],
        ['encoder/php/hex', nil],
        ['encoder/php/minify', nil],
        ['encoder/generic/none', nil],
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/x64/xor', nil],
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/cmd/base64', nil],
      ])
    end

    it 'selects a PHP encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('php/')
    end

    it 'selects the first native encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/php/base64')
    end

    it 'does not select x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('zutto_dekiru')
    end

    it 'does not select x86/shikata_ga_nai' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('shikata_ga_nai')
    end

    it 'does not select cmd/base64' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('cmd/')
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
        ['encoder/php/base64', nil],
        ['encoder/x86/shikata_ga_nai', nil],
      ])
    end

    it 'selects an x64 encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('x64/')
    end

    it 'prefers x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/x64/zutto_dekiru')
    end

    it 'does not select php/base64' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('php/')
    end

    it 'does not select x86/shikata_ga_nai' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x86/')
    end
  end

  context 'with an x86 payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'windows/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_X86])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/x86/fnstenv_mov', nil],
        ['encoder/x86/call4_dword_xor', nil],
        ['encoder/generic/none', nil],
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/php/base64', nil],
      ])
    end

    it 'selects an x86 encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('x86/')
    end

    it 'prefers x86/shikata_ga_nai' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/x86/shikata_ga_nai')
    end

    it 'does not select x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x64/')
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
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/x64/zutto_dekiru', nil],
      ])
    end

    it 'selects a cmd encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('cmd/')
    end

    it 'prefers cmd/base64' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/cmd/base64')
    end

    it 'does not select x86/shikata_ga_nai' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x86/')
    end

    it 'does not select x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x64/')
    end
  end

  context 'with a ruby payload' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'ruby/shell_reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_RUBY])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/ruby/base64', nil],
        ['encoder/generic/none', nil],
        ['encoder/x64/zutto_dekiru', nil],
      ])
    end

    it 'selects a ruby encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('ruby/')
    end

    it 'selects the first native encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/ruby/base64')
    end

    it 'does not select x64/zutto_dekiru' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x64/')
    end
  end

  # --- generic/none fallback ---

  context 'when only generic/none matches the architecture filter' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'python/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PYTHON])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/generic/none', nil],
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/x86/shikata_ga_nai', nil],
      ])
    end

    it 'falls back to generic/none' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/generic/none')
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
  end

  # --- No native encoders available (fallback to full list) ---

  context 'when no native encoders exist and no generic' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'java/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_JAVA])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/x64/zutto_dekiru', nil],
      ])
    end

    it 'falls back to the full compatible list' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to be_nil
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
  end

  context 'with multi-arch payload (first arch wins)' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'linux/x86/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_X86, ARCH_X64])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/x86/shikata_ga_nai', nil],
        ['encoder/x64/zutto_dekiru', nil],
        ['encoder/generic/none', nil],
      ])
    end

    it 'selects encoder matching the first arch' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('x86/')
    end

    it 'does not select encoder from secondary arch' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x64/')
    end
  end

  context 'with payload arch that has no preferred encoder' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'linux/mipsle/shell/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_MIPSLE])
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/mipsle/byte_xori', nil],
        ['encoder/mipsle/longxor', nil],
        ['encoder/generic/none', nil],
        ['encoder/x86/shikata_ga_nai', nil],
      ])
    end

    it 'selects a native arch encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to include('mipsle/')
    end

    it 'does not select x86 encoder' do
      chosen = described_class.choose_encoder(mod)
      expect(chosen).not_to include('x86/')
    end
  end

  # --- Encoder selection within same arch ---

  context 'encoder selection within same arch' do
    before(:each) do
      datastore.import_options_from_hash({ 'PAYLOAD' => 'php/meterpreter/reverse_tcp' })
      allow(payload).to receive(:arch).and_return([ARCH_PHP])
    end

    it 'selects the first native encoder from filtered list' do
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/php/hex', nil],
        ['encoder/php/base64', nil],
      ])
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/php/hex')
    end

    it 'picks first from filtered list when no preferred matches' do
      allow(payload).to receive(:compatible_encoders).and_return([
        ['encoder/generic/none', nil],
        ['encoder/php/hex', nil],
        ['encoder/php/minify', nil],
      ])
      chosen = described_class.choose_encoder(mod)
      expect(chosen).to eq('encoder/generic/none')
    end
  end
end
