# frozen_string_literal: true

require 'spec_helper'
require 'support/reporting/shared_examples'

RSpec.describe Msf::Reporting::Backends::InMemoryBackend do
  subject(:backend) { described_class.new }

  def simulate_db_inactive!
    backend.db_inactive!
  end

  def inject_failure(method, error)
    backend.fail_next!(method, error)
  end

  it_behaves_like 'a reporting backend'

  describe '#calls' do
    it 'records every call in declaration order with method, entity_type, and frozen kwargs' do
      backend.report_host(address: '192.0.2.10')
      backend.report_service(host: 1, port: 80, proto: 'tcp')

      expect(backend.calls.length).to eq(2)
      expect(backend.calls[0][:method]).to eq(:report_host)
      expect(backend.calls[0][:entity_type]).to eq(:host)
      expect(backend.calls[0][:kwargs]).to eq(address: '192.0.2.10')
      expect(backend.calls[0][:kwargs]).to be_frozen
      expect(backend.calls[1][:method]).to eq(:report_service)
    end

    it 'returns ascending row_ids for successive Persisted results' do
      r1 = backend.report_host(address: '192.0.2.10')
      r2 = backend.report_host(address: '192.0.2.11')

      expect(r2.row_id).to be > r1.row_id
    end
  end

  describe '#fail_next!' do
    it 'consumes one queued failure per matching call' do
      backend.fail_next!(:report_host, Msf::Reporting::BackendError.new('1'))

      expect(backend.report_host(address: '192.0.2.10')).to be_a(Msf::Reporting::Results::Failed)
      expect(backend.report_host(address: '192.0.2.11')).to be_a(Msf::Reporting::Results::Persisted)
    end
  end

  describe '#reset!' do
    it 'clears recorded calls and failure injections' do
      backend.report_host(address: '192.0.2.10')
      backend.fail_next!(:report_host, Msf::Reporting::BackendError.new('x'))

      backend.reset!

      expect(backend.calls).to be_empty
      expect(backend.report_host(address: '192.0.2.11')).to be_a(Msf::Reporting::Results::Persisted)
    end
  end

  describe '#report_session' do
    let(:session) { Object.new }

    it 'records both the compound entry and per-step single-entity calls' do
      backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session
      )

      methods = backend.calls.map { |c| c[:method] }
      expect(methods).to include(:report_session, :report_host, :report_service, :persist_session)
    end

    it 'raises Msf::Reporting::CompoundError on :failed when raise_on_failure (default) is true' do
      backend.fail_next!(:report_host, Msf::Reporting::BackendError.new('host failure'))

      expect do
        backend.report_session(
          host: { address: '192.0.2.10' },
          service: { port: 445, proto: 'tcp' },
          session: session
        )
      end.to raise_error(Msf::Reporting::CompoundError)
    end

    it 'returns the Compound result without raising when raise_on_failure: false' do
      backend.fail_next!(:report_host, Msf::Reporting::BackendError.new('host failure'))

      result = backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session,
        raise_on_failure: false
      )

      expect(result).to be_a(Msf::Reporting::Results::Compound)
      expect(%i[partial failed]).to include(result.overall)
    end

    it 'omits optional vuln/exploit_attempt steps when not given' do
      result = backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session
      )

      expect(result.steps.map(&:entity_type)).not_to include(:vuln, :exploit_attempt)
    end

    it 'includes optional vuln/exploit_attempt steps when given' do
      result = backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session,
        vuln: { name: 'CVE-2024-XXXX' },
        exploit_attempt: { module: 'exploit/multi/foo', attempted_at: Time.now }
      )

      expect(result.steps.map(&:entity_type)).to include(:vuln, :exploit_attempt)
    end
  end

  describe 'method coverage' do
    it 'implements every method named in ENTITY_TYPE_BY_METHOD' do
      described_class::ENTITY_TYPE_BY_METHOD.each_key do |method|
        expect(backend).to respond_to(method)
      end
    end
  end
end
