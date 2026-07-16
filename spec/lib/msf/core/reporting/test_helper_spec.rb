# frozen_string_literal: true

require 'spec_helper'
require 'support/reporting/test_helper'

RSpec.describe Msf::Reporting::TestHelper do
  describe 'inclusion' do
    it 'exposes a fresh InMemoryBackend as #reporter via let' do
      group = RSpec::Core::ExampleGroup.describe('inclusion smoke') do
        include Msf::Reporting::TestHelper
      end

      group.run

      example = group.new
      expect(example.reporter).to be_a(Msf::Reporting::Backends::InMemoryBackend)
      expect(example.reporter.calls).to be_empty
    end
  end

  describe 'have_reported matcher' do
    let(:backend) { Msf::Reporting::Backends::InMemoryBackend.new }

    it 'matches when an entity of the given type was reported' do
      backend.report_host(address: '192.0.2.10')
      expect(backend).to have_reported(:host)
    end

    it 'fails to match when no call of that entity_type was made' do
      backend.report_host(address: '192.0.2.10')
      expect(backend).not_to have_reported(:vuln)
    end

    it 'matches on a subset of fields' do
      backend.report_service(host: 1, port: 80, proto: 'tcp', name: 'http')
      expect(backend).to have_reported(:service, port: 80)
      expect(backend).to have_reported(:service, proto: 'tcp', name: 'http')
    end

    it 'does not match when a specified field differs from the recorded call' do
      backend.report_host(address: '192.0.2.10')
      expect(backend).not_to have_reported(:host, address: '192.0.2.99')
    end

    it 'does not match when a specified field is absent from the recorded call' do
      backend.report_host(address: '192.0.2.10')
      expect(backend).not_to have_reported(:host, name: 'absent')
    end

    describe 'count modifiers' do
      before do
        backend.report_host(address: '192.0.2.10')
        backend.report_host(address: '192.0.2.11')
        backend.report_host(address: '192.0.2.12')
      end

      it 'enforces exactly(N).times' do
        expect(backend).to have_reported(:host).exactly(3).times
        expect(backend).not_to have_reported(:host).exactly(2).times
      end

      it 'enforces at_least(N).time(s)' do
        expect(backend).to have_reported(:host).at_least(2).times
        expect(backend).not_to have_reported(:host).at_least(4).times
      end

      it 'enforces at_most(N).time(s)' do
        expect(backend).to have_reported(:host).at_most(3).times
        expect(backend).not_to have_reported(:host).at_most(2).times
      end

      it 'combines field-subset matching with count modifiers' do
        expect(backend).to have_reported(:host, address: '192.0.2.10').exactly(1).time
      end
    end

    describe 'ordering' do
      it 'preserves recording order on the underlying #calls list' do
        backend.report_host(address: '192.0.2.10')
        backend.report_service(host: 1, port: 80, proto: 'tcp')
        backend.report_host(address: '192.0.2.11')

        entity_order = backend.calls.map { |c| c[:entity_type] }
        expect(entity_order).to eq(%i[host service host])
      end
    end
  end
end
