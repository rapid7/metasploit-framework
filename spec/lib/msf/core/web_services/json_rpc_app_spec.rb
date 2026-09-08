# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::WebServices::JsonRpcApp do
  # Sinatra settings are class level, so capture and restore the real values rather
  # than resetting to nil, which would discard the environment derived configuration
  # for the remainder of the process.
  let!(:original_api_token) { described_class.settings.api_token }
  let!(:original_db_manager) { described_class.settings.db_manager }
  let!(:original_data_service_url) { described_class.settings.data_service_url }

  after do
    described_class.settings.api_token = original_api_token
    described_class.settings.db_manager = original_db_manager
    described_class.settings.data_service_url = original_data_service_url
  end

  describe '.boot!' do
    let(:db) { instance_double(Msf::DBManager) }
    let(:framework) { double('framework', db: db) }

    before do
      allow(described_class.settings).to receive(:framework).and_return(framework)
      described_class.settings.api_token = nil
      described_class.settings.db_manager = nil
      described_class.settings.data_service_url = nil
    end

    context 'when an API token is configured' do
      before do
        described_class.settings.api_token = 'static_token_abc123'
      end

      it 'does not raise' do
        expect { described_class.boot! }.not_to raise_error
      end

      it 'does not touch the database' do
        expect(db).not_to receive(:active)
        expect(db).not_to receive(:users)
        described_class.boot!
      end

      it 'leaves db_manager nil' do
        described_class.boot!
        expect(described_class.settings.db_manager).to be_nil
      end

      it 'retains the token' do
        described_class.boot!
        expect(described_class.settings.api_token).to eq('static_token_abc123')
      end
    end

    context 'when the API token is too short' do
      before do
        described_class.settings.api_token = 'short'
      end

      it 'raises rather than accepting a guessable token' do
        expect { described_class.boot! }.to raise_error(
          described_class::BootError,
          /must be at least #{described_class::MIN_API_TOKEN_LENGTH} characters/
        )
      end
    end

    # An empty MSF_WS_JSON_RPC_API_TOKEN would otherwise authenticate any request
    # presenting an equally empty token.
    ['', '   '].each do |blank|
      context "when the API token is blank (#{blank.inspect})" do
        before do
          described_class.settings.api_token = blank
          allow(db).to receive(:active).and_return(true)
          allow(db).to receive(:users).with({}).and_return([instance_double(Mdm::User, persistence_token: SecureRandom.hex(20))])
        end

        it 'discards the token' do
          described_class.boot!
          expect(described_class.settings.api_token).to be_nil
        end

        it 'falls back to database authentication' do
          described_class.boot!
          expect(described_class.settings.db_manager).to eq(db)
        end
      end
    end

    context 'when the database is available and has users' do
      before do
        allow(db).to receive(:active).and_return(true)
        allow(db).to receive(:users).with({}).and_return([instance_double(Mdm::User, persistence_token: SecureRandom.hex(20))])
      end

      it 'does not raise' do
        expect { described_class.boot! }.not_to raise_error
      end

      it 'sets db_manager' do
        described_class.boot!
        expect(described_class.settings.db_manager).to eq(db)
      end

      it 'leaves the API token unset' do
        described_class.boot!
        expect(described_class.settings.api_token).to be_nil
      end
    end

    # Refusing to start is deliberate: the alternative is serving RPC unauthenticated.
    shared_examples 'refuses to start' do |reason, remedy = /Set MSF_WS_JSON_RPC_API_TOKEN.*or run 'msfdb init'/m|
      it 'raises a BootError' do
        expect { described_class.boot! }.to raise_error(described_class::BootError, reason)
      end

      it 'explains how to configure authentication' do
        expect { described_class.boot! }.to raise_error(described_class::BootError, remedy)
      end

      it 'does not set db_manager' do
        expect { described_class.boot! }.to raise_error(described_class::BootError)
        expect(described_class.settings.db_manager).to be_nil
      end

      it 'does not invent a token' do
        expect { described_class.boot! }.to raise_error(described_class::BootError)
        expect(described_class.settings.api_token).to be_nil
      end
    end

    context 'when the database is unavailable' do
      before do
        allow(db).to receive(:active).and_return(false)
      end

      include_examples 'refuses to start', /the database is not available/

      it 'does not try to read users from an inactive database' do
        expect(db).not_to receive(:users)
        expect { described_class.boot! }.to raise_error(described_class::BootError)
      end
    end

    context 'when the database is active but cannot be queried' do
      before do
        allow(db).to receive(:active).and_return(true)
        allow(db).to receive(:users).with({}).and_raise(StandardError, 'connection refused')
      end

      include_examples 'refuses to start', /could not be queried/

      it 'includes the underlying error' do
        expect { described_class.boot! }.to raise_error(described_class::BootError, /connection refused/)
      end
    end

    context 'when the database is available but has no users' do
      before do
        allow(db).to receive(:active).and_return(true)
        allow(db).to receive(:users).with({}).and_return([])
      end

      include_examples 'refuses to start', /the database holds no users/
    end

    # A data proxy with no registered data service answers every call with nil rather
    # than raising, so a nil user list must not be mistaken for a usable database.
    context 'when the database returns no user list at all' do
      before do
        allow(db).to receive(:active).and_return(true)
        allow(db).to receive(:users).with({}).and_return(nil)
      end

      include_examples 'refuses to start', /the database holds no users/
    end

    # report_user does not issue an API token, so a database of password-only accounts is
    # reachable. This application only validates persistence_token, so starting against one
    # would 401 every request.
    [nil, '', '   '].each do |token|
      context "when the only user has no usable API token (#{token.inspect})" do
        before do
          allow(db).to receive(:active).and_return(true)
          allow(db).to receive(:users).with({})
                                      .and_return([instance_double(Mdm::User, persistence_token: token)])
        end

        include_examples 'refuses to start',
                         /no user in the database has an API token/,
                         %r{POST /api/v1/auth/generate-token}
      end
    end

    context 'when only some users have an API token' do
      before do
        allow(db).to receive(:active).and_return(true)
        allow(db).to receive(:users).with({}).and_return(
          [
            instance_double(Mdm::User, persistence_token: nil),
            instance_double(Mdm::User, persistence_token: SecureRandom.hex(20))
          ]
        )
      end

      it 'starts, because one usable token is enough' do
        described_class.boot!
        expect(described_class.settings.db_manager).to eq(db)
      end
    end

    # User accounts of a remote data service live on that service, so its tokens cannot be
    # validated here. The local database Active Record needs alongside it holds a different
    # set of users, and authenticating against those would accept credentials that were
    # never issued for this service.
    context 'when a remote data service is configured' do
      before do
        described_class.settings.data_service_url = 'https://192.0.2.1:5443'
      end

      it 'refuses to start without a static token' do
        expect { described_class.boot! }.to raise_error(
          described_class::BootError,
          %r{cannot be validated against the remote data service https://192.0.2.1:5443}
        )
      end

      it 'does not authenticate against the local database' do
        expect(db).not_to receive(:users)
        expect { described_class.boot! }.to raise_error(described_class::BootError)
        expect(described_class.settings.db_manager).to be_nil
      end

      it 'starts when a static token is configured' do
        described_class.settings.api_token = 'static_token_abc123'
        expect { described_class.boot! }.not_to raise_error
      end
    end
  end
end
