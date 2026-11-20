require 'spec_helper'
require 'rex/post/meterpreter/micro_helper'

RSpec.describe Rex::Post::Meterpreter::MicroHelper do
  let(:client) { double('client') }
  let(:shell) { double('shell', client: client) }
  let(:helper_class) do
    described_class.compile(<<~'SOURCE', 'inline-helper')
      command 'download', 'Download a file' do |path|
        @downloaded = path
      end

      def downloaded
        @downloaded
      end

      on_unload do
        @cleaned = true
      end
    SOURCE
  end
  let(:helper) { helper_class.new(shell, profile: 'test', object_name: 'micro-download', channel_types: ['micro_file_download/v1']) }

  it 'compiles and invokes manifest helper commands' do
    expect(helper.commands).to eq('download' => 'Download a file')
    helper.invoke_command('download', ['remote.txt'])
    expect(helper.downloaded).to eq('remote.txt')
  end

  it 'runs its cleanup handler' do
    helper.cleanup
    expect(helper.instance_variable_get(:@cleaned)).to be(true)
  end

  it 'rejects undeclared channel types' do
    expect { helper.open_pool_channel('other') }.to raise_error(ArgumentError, 'Undeclared helper channel type: other')
  end
end
