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

  describe '#mmh3_x86_32' do
    # Canonical MurmurHash3 x86 32-bit vectors (seed 0), signed, matching the
    # Python mmh3 library that Shodan and nuclei favicon hashes use.
    {
      '' => 0,
      'foo' => -156_908_512,
      'hello' => 613_153_351,
      'test' => -1_167_338_989
    }.each do |input, expected|
      it "hashes #{input.inspect} to #{expected}" do
        expect(subject.mmh3_x86_32(input)).to eq(expected)
      end
    end
  end

  describe '#favicon_mmh3' do
    # A 121-byte body is long enough that the Shodan-style 76-character base64
    # line wrap (as opposed to Ruby's 60-character Base64.encode64) changes the
    # hash, so this also guards the encoding.
    let(:favicon_body) { (0..120).map(&:chr).join.b }

    def http_response(code, body)
      instance_double(Rex::Proto::Http::Response, code: code, body: body)
    end

    it 'computes the Shodan-compatible hash of the served favicon' do
      allow(subject).to receive(:send_request_cgi).and_return(http_response(200, favicon_body))
      expect(subject.favicon_mmh3).to eq(-714_917_412)
    end

    it 'returns nil when no favicon is served' do
      allow(subject).to receive(:send_request_cgi).and_return(http_response(404, ''))
      expect(subject.favicon_mmh3).to be_nil
    end

    it 'returns nil when the request fails' do
      allow(subject).to receive(:send_request_cgi).and_return(nil)
      expect(subject.favicon_mmh3).to be_nil
    end
  end
end
