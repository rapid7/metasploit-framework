# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Reporting::Reporter do
  describe '#initialize' do
    it 'defaults the driver to :in_memory when no framework is given' do
      reporter = described_class.new
      expect(reporter.driver).to eq(:in_memory)
    end

    it 'accepts an explicit driver from the known set' do
      Msf::Reporting::Reporter::KNOWN_DRIVERS.each do |driver|
        expect(described_class.new(driver: driver).driver).to eq(driver)
      end
    end

    it 'rejects an unknown driver with Msf::Reporting::Error' do
      expect do
        described_class.new(driver: :sqlite)
      end.to raise_error(Msf::Reporting::Error, /unknown reporting driver/)
    end

    it 'reads the driver from framework.db.driver when not given explicitly' do
      db = double('db', driver: :db_manager)
      framework = double('framework', db: db)
      reporter = described_class.new(framework: framework, backend: double('backend'))
      expect(reporter.driver).to eq(:db_manager)
    end

    it 'normalises the legacy "postgresql" driver string to :db_manager' do
      db = double('db', driver: 'postgresql')
      framework = double('framework', db: db)
      reporter = described_class.new(framework: framework, backend: double('backend'))
      expect(reporter.driver).to eq(:db_manager)
    end

    it 'normalises the legacy "http" driver string to :http' do
      db = double('db', driver: 'http')
      framework = double('framework', db: db)
      reporter = described_class.new(framework: framework, backend: double('backend'))
      expect(reporter.driver).to eq(:http)
    end

    it 'builds an InMemoryBackend when the driver is :in_memory and no framework is given' do
      reporter = described_class.new(driver: :in_memory)
      expect(reporter.backend).to be_a(Msf::Reporting::Backends::InMemoryBackend)
    end

    it 'builds a DbManagerBackend when the driver is :db_manager' do
      framework = double('framework', db: double('db', driver: :db_manager))
      reporter = described_class.new(framework: framework, driver: :db_manager)
      expect(reporter.backend).to be_a(Msf::Reporting::Backends::DbManagerBackend)
    end

    it 'leaves backend nil for the :http driver' do
      reporter = described_class.new(driver: :http)
      expect(reporter.backend).to be_nil
    end

    it 'accepts an explicit backend instance overriding driver-based construction' do
      injected = double('backend')
      reporter = described_class.new(driver: :in_memory, backend: injected)
      expect(reporter.backend).to be(injected)
    end
  end

  describe 'stub single-entity methods' do
    subject(:reporter) { described_class.new }

    %i[report_service report_vuln report_note report_loot].each do |method|
      it "#{method} returns a Skipped(:not_implemented) result tagged with the right entity_type" do
        result = reporter.public_send(method, foo: :bar)
        expect(result).to be_a(Msf::Reporting::Results::Skipped)
        expect(result.reason).to eq(:not_implemented)
        expect(result.entity_type).to be_a(Symbol)
      end
    end
  end

  describe '#report_host' do
    it 'delegates to the resolved backend' do
      injected = double('backend')
      expect(injected).to receive(:report_host).with(address: '192.0.2.10').and_return(:sentinel)

      reporter = described_class.new(driver: :in_memory, backend: injected)
      expect(reporter.report_host(address: '192.0.2.10')).to eq(:sentinel)
    end

    it 'returns Skipped(:not_implemented) when the resolved backend is nil (e.g. :http)' do
      reporter = described_class.new(driver: :http)
      result = reporter.report_host(address: '192.0.2.10')
      expect(result).to be_a(Msf::Reporting::Results::Skipped)
      expect(result.reason).to eq(:not_implemented)
      expect(result.entity_type).to eq(:host)
    end
  end

  describe '#report_session' do
    it 'returns a Compound result while compound wiring is unimplemented' do
      result = described_class.new.report_session(host: {}, service: {}, session: nil)
      expect(result).to be_a(Msf::Reporting::Results::Compound)
      expect(result.steps).to eq([])
      expect(result.overall).to eq(:skipped_db_inactive)
    end
  end

  describe '#current_execution' do
    it 'returns nil from the stub' do
      expect(described_class.new.current_execution).to be_nil
    end
  end
end
