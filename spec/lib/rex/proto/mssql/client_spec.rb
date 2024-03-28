# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/mysql/client'

RSpec.describe Rex::Proto::MSSQL::Client do
  let(:host) { '127.0.0.1' }
  let(:port) { 1234 }
  let(:info) { "#{host}:#{port}" }
  let(:db_name) { 'my_db_name' }
  let(:framework_module) { ::Msf::Module.new }

  subject do
    client = described_class.new(framework_module, nil, host, port)
    client.current_database = db_name
    client
  end

  it_behaves_like 'session compatible SQL client'

  describe '#current_database' do
    context 'we have not selected a database yet' do
      subject do
        described_class.new(framework_module, nil, host, port)
      end

      it 'returns an empty database name' do
        expect(subject.current_database).to eq('')
      end
    end
  end
end
