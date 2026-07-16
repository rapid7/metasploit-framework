# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::Results do
  describe Msf::Reporting::Results::Persisted do
    subject(:persisted) { described_class.new(entity_type: :host, row_id: 7, row: :a_row) }

    it 'exposes its kwargs' do
      expect(persisted.entity_type).to eq(:host)
      expect(persisted.row_id).to eq(7)
      expect(persisted.row).to eq(:a_row)
    end

    it 'defaults touched to false' do
      expect(persisted.touched).to be(false)
    end

    it 'accepts touched: true to mark the find-or-create / touched-by case' do
      result = described_class.new(entity_type: :host, row_id: 1, touched: true)
      expect(result.touched).to be(true)
    end

    it 'reports the correct predicates' do
      expect(persisted).to be_persisted
      expect(persisted).not_to be_skipped
      expect(persisted).not_to be_failed
    end

    it 'requires entity_type and row_id' do
      expect { described_class.new(entity_type: :host) }.to raise_error(ArgumentError)
      expect { described_class.new(row_id: 1) }.to raise_error(ArgumentError)
    end
  end

  describe Msf::Reporting::Results::Skipped do
    subject(:skipped) { described_class.new(entity_type: :host, reason: :db_inactive) }

    it 'carries entity_type and reason' do
      expect(skipped.entity_type).to eq(:host)
      expect(skipped.reason).to eq(:db_inactive)
    end

    it 'reports the correct predicates' do
      expect(skipped).to be_skipped
      expect(skipped).not_to be_persisted
      expect(skipped).not_to be_failed
    end
  end

  describe Msf::Reporting::Results::Failed do
    let(:error) { Msf::Reporting::BackendError.new('boom') }

    subject(:failed) { described_class.new(entity_type: :host, error: error) }

    it 'carries entity_type and error' do
      expect(failed.entity_type).to eq(:host)
      expect(failed.error).to be(error)
    end

    it 'reports the correct predicates' do
      expect(failed).to be_failed
      expect(failed).not_to be_persisted
      expect(failed).not_to be_skipped
    end
  end

  describe Msf::Reporting::Results::SkippedDependencyFailed do
    subject(:dep) { described_class.new(entity_type: :service, parent: :host) }

    it 'carries entity_type and parent step name' do
      expect(dep.entity_type).to eq(:service)
      expect(dep.parent).to eq(:host)
    end

    it 'is treated as a skip, not a failure' do
      expect(dep).to be_skipped
      expect(dep).not_to be_failed
    end
  end

  describe Msf::Reporting::Results::Compound do
    let(:host_step) { Msf::Reporting::Results::Persisted.new(entity_type: :host, row_id: 1) }
    let(:service_step) { Msf::Reporting::Results::Persisted.new(entity_type: :service, row_id: 2) }

    it 'requires steps and overall' do
      expect { described_class.new(steps: []) }.to raise_error(ArgumentError)
      expect { described_class.new(overall: :ok) }.to raise_error(ArgumentError)
    end

    it 'rejects unknown overall values' do
      expect do
        described_class.new(steps: [], overall: :bogus)
      end.to raise_error(ArgumentError, /overall must be one of/)
    end

    it 'accepts every documented overall value' do
      %i[ok partial failed skipped_db_inactive].each do |overall|
        expect do
          described_class.new(steps: [host_step], overall: overall)
        end.not_to raise_error
      end
    end

    it 'exposes overall predicates' do
      ok = described_class.new(steps: [host_step, service_step], overall: :ok)
      partial = described_class.new(steps: [host_step], overall: :partial)
      failed = described_class.new(steps: [host_step], overall: :failed)
      skipped = described_class.new(steps: [], overall: :skipped_db_inactive)

      expect(ok).to be_ok
      expect(partial).to be_partial
      expect(failed).to be_failed
      expect(skipped).to be_skipped_db_inactive
    end
  end
end
