# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::WebServices::FrameworkExtension do
  describe '.db_connect' do
    let(:framework) { double('framework') }
    let(:settings) { double('settings', data_service_url: data_service_url) }
    let(:app) { double('app', settings: settings) }
    let(:data_service_url) { nil }

    before do
      allow(described_class).to receive(:warn)
    end

    context 'when the database connects successfully' do
      before do
        allow(Msf::DbConnector).to receive(:db_connect_from_config).with(framework).and_return({ result: 'Connected' })
      end

      it 'does not raise' do
        expect { described_class.db_connect(framework, app) }.not_to raise_error
      end

      it 'does not warn' do
        expect(described_class).not_to receive(:warn)
        described_class.db_connect(framework, app)
      end
    end

    # The JSON-RPC service supports running without a database, so a failed connection
    # must not prevent the framework - and therefore the service - from starting.
    context 'when the database is unavailable' do
      before do
        allow(Msf::DbConnector).to receive(:db_connect_from_config)
          .with(framework)
          .and_return({ error: 'Failed to connect to the Postgres data service: connection refused' })
      end

      it 'does not raise' do
        expect { described_class.db_connect(framework, app) }.not_to raise_error
      end

      it 'warns that the service is starting without database support' do
        expect(described_class).to receive(:warn).with(/without database support/)
        described_class.db_connect(framework, app)
      end
    end

    # Msf::DbConnector requires a live local database before it will attempt a remote
    # connection, and leaves it registered as the current data service when the remote one
    # fails. Continuing would silently serve and authenticate against that local database
    # instead of the service the operator named.
    context 'when a remote data service is configured but unreachable' do
      let(:data_service_url) { 'https://192.0.2.1:5443' }

      before do
        allow(settings).to receive(:data_service_api_token).and_return('token')
        allow(settings).to receive(:data_service_cert).and_return(nil)
        allow(settings).to receive(:data_service_skip_verify).and_return(false)
        allow(Msf::DbConnector).to receive(:db_connect).and_return({ error: 'Failed to connect' })
      end

      it 'raises rather than falling back to the local database' do
        expect { described_class.db_connect(framework, app) }
          .to raise_error(described_class::DataServiceError, /Failed to connect/)
      end

      it 'names the data service that could not be reached' do
        expect { described_class.db_connect(framework, app) }
          .to raise_error(described_class::DataServiceError, /#{Regexp.escape(data_service_url)}/)
      end

      it 'does not report it as starting without database support' do
        expect(described_class).not_to receive(:warn)
        expect { described_class.db_connect(framework, app) }.to raise_error(described_class::DataServiceError)
      end
    end

    context 'when a remote data service is configured and reachable' do
      let(:data_service_url) { 'https://192.0.2.1:5443' }

      before do
        allow(settings).to receive(:data_service_api_token).and_return('token')
        allow(settings).to receive(:data_service_cert).and_return(nil)
        allow(settings).to receive(:data_service_skip_verify).and_return(false)
        allow(Msf::DbConnector).to receive(:db_connect).and_return({ result: 'Connected' })
      end

      it 'does not raise' do
        expect { described_class.db_connect(framework, app) }.not_to raise_error
      end
    end
  end
end
