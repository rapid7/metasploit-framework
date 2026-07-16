# frozen_string_literal: true

require 'spec_helper'
require 'support/reporting/shared_examples'

RSpec.describe Msf::Reporting::Backends::DbManagerBackend do
  let(:fake_db) do
    db = double('Msf::DBManager')
    allow(db).to receive(:active).and_return(true)
    db
  end
  let(:framework) { double('Msf::Framework', db: fake_db) }

  subject(:backend) { described_class.new(framework: framework) }

  let(:fake_host) { double('Mdm::Host', id: 42) }

  before do
    # Bypass the ActiveRecord connection-pool checkout so specs run without
    # a live PostgreSQL connection. The end-to-end pool path is exercised by
    # the +ConnectionPool+ spec.
    allow(Msf::Reporting::ConnectionPool).to receive(:with_connection) { |&block| block.call }

    allow(fake_db).to receive(:report_host).and_return(fake_host)
  end

  def simulate_db_inactive!
    allow(fake_db).to receive(:active).and_return(false)
  end

  def inject_failure(method, error)
    # The backend wraps any +StandardError+ raised by +framework.db.<method>+
    # into a fresh +BackendError+ with the same message; raise the same
    # class/message the shared example queued so the assertion holds.
    allow(fake_db).to receive(method).and_raise(error.class, error.message)
  end

  it_behaves_like 'a reporting backend report_host'

  describe '#report_host' do
    it 'translates address: into the legacy :host opts key when delegating to framework.db' do
      expect(fake_db).to receive(:report_host).with(hash_including(host: '192.0.2.10', os_name: 'Linux')).and_return(fake_host)

      backend.report_host(address: '192.0.2.10', os_name: 'Linux')
    end

    it 'returns Skipped(:db_inactive) when framework.db.report_host returns nil' do
      allow(fake_db).to receive(:report_host).and_return(nil)

      result = backend.report_host(address: '192.0.2.10')
      expect(result).to be_a(Msf::Reporting::Results::Skipped)
      expect(result.reason).to eq(:db_inactive)
    end

    it 'returns Skipped(:db_inactive) without delegating when framework.db is inactive' do
      allow(fake_db).to receive(:active).and_return(false)
      expect(fake_db).not_to receive(:report_host)

      result = backend.report_host(address: '192.0.2.10')
      expect(result).to be_a(Msf::Reporting::Results::Skipped)
      expect(result.reason).to eq(:db_inactive)
    end

    it 'wraps a non-BackendError exception from framework.db.report_host into Failed(BackendError)' do
      allow(fake_db).to receive(:report_host).and_raise(ArgumentError, 'bad addr')

      result = backend.report_host(address: 'not-an-ip')
      expect(result).to be_a(Msf::Reporting::Results::Failed)
      expect(result.error).to be_a(Msf::Reporting::BackendError)
      expect(result.error.message).to eq('bad addr')
    end

    it 'preserves an already-typed BackendError raised by framework.db.report_host' do
      typed = Msf::Reporting::BackendError.new('typed')
      allow(fake_db).to receive(:report_host).and_raise(typed)

      result = backend.report_host(address: '192.0.2.10')
      expect(result.error).to be(typed)
    end

    it 'checks out an ActiveRecord connection via Msf::Reporting::ConnectionPool.with_connection' do
      expect(Msf::Reporting::ConnectionPool).to receive(:with_connection).and_call_original

      backend.report_host(address: '192.0.2.10')
    end

    it 'populates Persisted#row_id from the returned Mdm::Host id' do
      result = backend.report_host(address: '192.0.2.10')
      expect(result.row_id).to eq(42)
      expect(result.row).to be(fake_host)
      expect(result.touched).to be(false)
    end
  end
end
