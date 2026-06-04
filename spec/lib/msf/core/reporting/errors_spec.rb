# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Msf::Reporting error hierarchy' do
  it 'roots every reporting error at Msf::Reporting::Error' do
    [
      Msf::Reporting::ValidationError,
      Msf::Reporting::CompoundError,
      Msf::Reporting::DetachedSessionError,
      Msf::Reporting::BackendError,
      Msf::Reporting::DbInactiveError,
      Msf::Reporting::RemoteServiceError
    ].each do |klass|
      expect(klass.ancestors).to include(Msf::Reporting::Error)
    end
  end

  it 'roots Msf::Reporting::Error at StandardError so generic rescues still catch it' do
    expect(Msf::Reporting::Error.ancestors).to include(StandardError)
  end

  it 'nests DbInactiveError and RemoteServiceError under BackendError' do
    expect(Msf::Reporting::DbInactiveError.ancestors).to include(Msf::Reporting::BackendError)
    expect(Msf::Reporting::RemoteServiceError.ancestors).to include(Msf::Reporting::BackendError)
  end

  describe Msf::Reporting::ValidationError do
    it 'carries field/reason metadata and produces a sensible default message' do
      err = described_class.new(field: :address, reason: :missing)
      expect(err.field).to eq(:address)
      expect(err.reason).to eq(:missing)
      expect(err.message).to match(/missing required kwarg :address/)
    end

    it 'formats type errors with expected vs got' do
      err = described_class.new(field: :port, reason: :type, expected: Integer, got: 'oops')
      expect(err.message).to match(/expected Integer, got String/)
    end

    it 'formats enum errors with allowed and got values' do
      err = described_class.new(field: :proto, reason: :enum, allowed: %w[tcp udp], got: 'tcq')
      expect(err.allowed).to eq(%w[tcp udp])
      expect(err.message).to match(/not in \["tcp", "udp"\].*got "tcq"/)
    end

    it 'formats conflict errors with the offending field list' do
      err = described_class.new(reason: :conflict, fields: %i[host address])
      expect(err.fields).to eq(%i[host address])
      expect(err.message).to match(/conflicting kwargs/)
    end

    it 'accepts an explicit message override' do
      err = described_class.new('custom', field: :foo, reason: :missing)
      expect(err.message).to eq('custom')
    end
  end

  describe Msf::Reporting::CompoundError do
    it 'carries the underlying compound result' do
      result = Msf::Reporting::Results::Compound.new(steps: [], overall: :failed)
      err = described_class.new(result)

      expect(err.result).to be(result)
      expect(err.message).to match(/overall=:failed/)
    end
  end
end
