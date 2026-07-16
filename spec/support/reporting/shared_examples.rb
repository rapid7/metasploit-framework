# frozen_string_literal: true

# Shared examples enforcing the cross-backend parity contract. Every
# reporting backend MUST satisfy this suite identically; differences
# in the wire shape are bugs. The suite is split into per-method
# shared example groups so backends mid-migration can opt into just
# the parts they support.
#
# Each including spec MUST define:
#   let(:backend) { ... }                          # backend under test
#   def simulate_db_inactive!; ...; end            # put backend into :db_inactive
#   def inject_failure(method, error); ...; end    # next call to method returns Failed(error)

RSpec.shared_examples 'a reporting backend report_host' do
  describe '#report_host' do
    it 'returns Persisted with entity_type :host on a valid call' do
      result = backend.report_host(address: '192.0.2.10')

      expect(result).to be_a(Msf::Reporting::Results::Persisted)
      expect(result.entity_type).to eq(:host)
      expect(result.row_id).to be_a(Integer)
      expect(result.persisted?).to be(true)
    end

    context 'when the DB is inactive' do
      before { simulate_db_inactive! }

      it 'returns Skipped(reason: :db_inactive)' do
        result = backend.report_host(address: '192.0.2.10')

        expect(result).to be_a(Msf::Reporting::Results::Skipped)
        expect(result.entity_type).to eq(:host)
        expect(result.reason).to eq(:db_inactive)
      end
    end

    context 'when persistence fails' do
      before do
        inject_failure(:report_host, Msf::Reporting::BackendError.new('forced'))
      end

      it 'returns Failed carrying a typed BackendError (does NOT raise)' do
        expect do
          @result = backend.report_host(address: '192.0.2.10')
        end.not_to raise_error

        expect(@result).to be_a(Msf::Reporting::Results::Failed)
        expect(@result.entity_type).to eq(:host)
        expect(@result.error).to be_a(Msf::Reporting::BackendError)
      end
    end
  end
end

RSpec.shared_examples 'a reporting backend report_service' do
  describe '#report_service' do
    it 'returns Persisted with entity_type :service on a valid call' do
      result = backend.report_service(host: 1, port: 80, proto: 'tcp')

      expect(result).to be_a(Msf::Reporting::Results::Persisted)
      expect(result.entity_type).to eq(:service)
    end
  end
end

RSpec.shared_examples 'a reporting backend single-entity result hierarchy' do
  describe 'result hierarchy parity' do
    it 'never returns a value outside the documented Result hierarchy for single-entity calls' do
      result = backend.report_note(host: 1, type: 'host.os', data: 'linux')
      expect([
        Msf::Reporting::Results::Persisted,
        Msf::Reporting::Results::Skipped,
        Msf::Reporting::Results::Failed
      ]).to include(result.class)
    end
  end
end

RSpec.shared_examples 'a reporting backend report_session' do
  describe '#report_session (compound)' do
    let(:session) { Object.new }

    it 'returns a Compound with steps in the documented order' do
      result = backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session
      )

      expect(result).to be_a(Msf::Reporting::Results::Compound)
      expect(result.overall).to eq(:ok)
      expect(result.steps.map(&:entity_type)).to eq(%i[host service session])
    end

    it 'returns :skipped_db_inactive when the DB is inactive (raise_on_failure has no effect)' do
      simulate_db_inactive!

      result = backend.report_session(
        host: { address: '192.0.2.10' },
        service: { port: 445, proto: 'tcp' },
        session: session
      )

      expect(result.overall).to eq(:skipped_db_inactive)
    end
  end
end

# Umbrella suite: every method shared group above. Backends that have
# completed migration of every entity in scope include this; backends
# mid-migration cherry-pick the per-method groups they support.
RSpec.shared_examples 'a reporting backend' do
  it_behaves_like 'a reporting backend report_host'
  it_behaves_like 'a reporting backend report_service'
  it_behaves_like 'a reporting backend single-entity result hierarchy'
  it_behaves_like 'a reporting backend report_session'
end
