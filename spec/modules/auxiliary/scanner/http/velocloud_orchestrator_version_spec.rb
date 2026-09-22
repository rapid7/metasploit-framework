# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'auxiliary/scanner/http/velocloud_orchestrator_version' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/http/velocloud_orchestrator_version'
    )
  end

  describe '#vulnerable?' do
    # CVE-2026-93952 affected/fixed boundaries per release train.
    #   5.2: affected <= 5.2.3.15, fixed 5.2.3.16
    #   6.4: affected <= 6.4.2.7,  fixed 6.4.2.8
    #   6.1: affected <= 6.1.3.7,  fix pending
    #   7.0: affected <= 7.0.0.2,  fix pending
    [
      ['5.2.3.15', true],
      ['5.2.3.16', false],
      ['5.2.4.0', false],
      ['6.4.2.7', true],
      ['6.4.2.8', false],
      ['6.1.3.6', true],
      ['6.1.3.7', true],
      ['6.1.3.8', false],
      ['7.0.0.1', true],
      ['7.0.0.2', true],
      ['7.0.0.3', false]
    ].each do |version, expected|
      it "returns #{expected.inspect} for #{version}" do
        expect(subject.vulnerable?(Rex::Version.new(version))).to eq(expected)
      end
    end

    context 'with a version in an unrecognized release train' do
      it 'returns nil for an older train' do
        expect(subject.vulnerable?(Rex::Version.new('4.0.0.0'))).to be_nil
      end

      it 'returns nil for a newer train' do
        expect(subject.vulnerable?(Rex::Version.new('8.0.0.0'))).to be_nil
      end
    end
  end
end
