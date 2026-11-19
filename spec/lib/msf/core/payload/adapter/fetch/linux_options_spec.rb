require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Payload::Adapter::Fetch::LinuxOptions do
  let(:base_class) do
    Class.new do
      attr_reader :registered

      def initialize(_info = {})
        @registered = []
      end

      def register_options(opts, *)
        @registered.concat(opts)
      end
    end
  end

  def fetch_command_for(protocol)
    host = Class.new(base_class) do
      include Msf::Payload::Adapter::Fetch::LinuxOptions

      define_method(:fetch_protocol) { protocol }
    end.new
    Msf::OptionContainer.new(host.registered)['FETCH_COMMAND']
  end

  context 'with an FTP adapter' do
    let(:option) { fetch_command_for('FTP') }

    it 'defaults to FTP' do
      expect(option.default).to eq('FTP')
    end

    it 'only accepts the clients that have an FTP code path' do
      expect(option.enums).to eq(%w[FTP TNFTP GET])
    end

    it 'rejects a client without an FTP code path' do
      expect(option.valid?('CURL')).to be false
    end
  end

  %w[HTTP HTTPS TFTP].each do |protocol|
    context "with a #{protocol} adapter" do
      let(:option) { fetch_command_for(protocol) }

      it 'still defaults to CURL' do
        expect(option.default).to eq('CURL')
      end

      it 'still accepts every client' do
        expect(option.enums).to eq(%w[CURL FTP GET TFTP TNFTP WGET])
      end
    end
  end
end
