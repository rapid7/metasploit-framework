# frozen_string_literal: true

require 'rspec'
require_relative 'datastore_formatting'

RSpec.describe Acceptance::DatastoreFormatting do
  let(:formatter) { Object.new.extend(described_class) }

  describe '#format_datastore_options' do
    it 'formats simple key=value pairs' do
      expect(formatter.format_datastore_options({ RHOSTS: '192.0.2.1', RPORT: 1433 })).to eq('RHOSTS=192.0.2.1 RPORT=1433')
    end

    it 'quotes values containing spaces' do
      expect(formatter.format_datastore_options({ CMD: 'echo hello' })).to eq('CMD="echo hello"')
    end

    it 'escapes double quotes within values' do
      expect(formatter.format_datastore_options({ CMD: 'say "hi"' })).to eq('CMD="say \\"hi\\""')
    end

    it 'quotes values containing single quotes' do
      expect(formatter.format_datastore_options({ CMD: "it's" })).to eq(%q(CMD="it's"))
    end

    it 'quotes values containing backslashes' do
      expect(formatter.format_datastore_options({ USERNAME: 'DEV-AD\\Administrator' })).to eq('USERNAME="DEV-AD\\Administrator"')
    end

    it 'preserves backslashes in quoted values with spaces' do
      expect(formatter.format_datastore_options({ PATH: 'C:\\Program Files' })).to eq('PATH="C:\\Program Files"')
    end

    it 'returns empty string for empty hash' do
      expect(formatter.format_datastore_options({})).to eq('')
    end
  end
end
