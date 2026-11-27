# frozen_string_literal: true

require 'tmpdir'
require 'rex/parser/ini'
require 'msf/base/config'

RSpec.describe Msf::Config do
  subject(:config) { described_class.new }

  let(:path) { config.config_file }
  let(:original) { "[existing]\nsetting=keep\n" }

  around do |example|
    Dir.mktmpdir do |directory|
      config['ConfigDirectory'] = directory
      example.run
    end
  end

  {
    save: ->(config) { config.save('new' => { 'setting' => 'added' }) },
    delete_group: ->(config) { config.delete_group('missing') }
  }.each do |operation, mutate|
    it "leaves the configuration intact when #{operation} cannot read it" do
      File.write(path, original)
      read_error = Errno::EIO.new(path)
      allow(IO).to receive(:readlines).and_call_original
      allow(IO).to receive(:readlines).with(path).and_raise(read_error)

      aggregate_failures do
        expect { mutate.call(config) }.to raise_error(Errno::EIO) { |error| expect(error).to equal(read_error) }
        expect(File.binread(path)).to eq(original)
      end
    end
  end

  it 'saves to an explicit configuration file without serializing the path option' do
    alternate = "#{path}.alternate"
    File.write(alternate, original)
    options = { 'ConfigFile' => alternate, 'new' => { 'setting' => 'added' } }

    expect(config.save(options)).to be_nil
    expect(config.load(alternate)).to eq(
      'existing' => { 'setting' => 'keep' },
      'new' => { 'setting' => 'added' }
    )
    expect(File).not_to exist(path)
    expect(options['ConfigFile']).to eq(alternate)
  end

  it 'creates the configuration when it is missing' do
    expect(config.save('new' => { 'setting' => 'added' })).to be_nil
    expect(File.binread(path)).to eq("[new]\nsetting=added\n\n")
  end

  it 'preserves unrelated groups during successful saves and deletions' do
    File.write(path, original)
    config.save('new' => { 'setting' => 'added' })
    expect(config.load).to include('existing' => { 'setting' => 'keep' })

    expect(config.delete_group('existing')).to be_nil
    expect(config.load).to eq('new' => { 'setting' => 'added' })
  end
end
