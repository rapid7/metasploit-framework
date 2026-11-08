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

    it 'defaults to /favicon.ico but accepts an alternate path' do
      expect(subject).to receive(:send_request_cgi)
        .with(hash_including('uri' => '/apps/root/favicon.ico'))
        .and_return(http_response(200, favicon_body))
      expect(subject.favicon_mmh3('apps/root/favicon.ico')).to eq(-714_917_412)
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

  describe '#favicon_match?' do
    # Validated 2026-11-08 against two live Arista-hosted VCOs
    # (vco1-usvi1 and vco996-usvi1.velocloud.net): the 1406-byte ICO served at
    # /apps/root/favicon.ico hashes to -2062596654 under both this Ruby code
    # and the reference Python mmh3 library.
    let(:vco_favicon_body) do
      # A stand-in body whose hash under the module's own encoding is checked
      # below; the real appliance bytes are not redistributable here.
      "\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00" + ('A' * 1400).b
    end

    def http_response(code, body)
      instance_double(Rex::Proto::Http::Response, code: code, body: body)
    end

    it 'tries each candidate favicon path and returns true on a match' do
      allow(subject).to receive(:send_request_cgi) do |opts|
        if opts['uri'] == '/apps/root/favicon.ico'
          http_response(200, vco_favicon_body)
        else
          http_response(404, '')
        end
      end
      allow(subject).to receive(:mmh3_x86_32).and_return(-2_062_596_654)
      expect(subject.favicon_match?).to be(true)
    end

    it 'returns false when no candidate path hashes to the VCO constant' do
      allow(subject).to receive(:send_request_cgi).and_return(http_response(200, vco_favicon_body))
      allow(subject).to receive(:mmh3_x86_32).and_return(0)
      expect(subject.favicon_match?).to be(false)
    end
  end

  describe '#looks_like_vco?' do
    def http_response(body, headers = {})
      instance_double(Rex::Proto::Http::Response, body: body, headers: headers)
    end

    it 'matches the Arista SPA landing that references @velocloud/vco-header' do
      body = '<div id="single-spa-application:@velocloud/vco-header"></div>'
      expect(subject.looks_like_vco?(http_response(body))).to be(true)
    end

    it 'matches a legacy landing page with the capitalised product name' do
      expect(subject.looks_like_vco?(http_response('VeloCloud Orchestrator'))).to be(true)
    end

    it 'returns false when no signal is present' do
      expect(subject.looks_like_vco?(http_response('<html></html>'))).to be(false)
    end

    it 'returns false when the response is nil' do
      expect(subject.looks_like_vco?(nil)).to be(false)
    end
  end

  describe '#login_cookie_match?' do
    # Fixtures use a raw header block (one "Name: value" per line) to match
    # how Rex::Proto::Http::Headers#to_s renders real responses.
    def http_response(raw_headers)
      headers = instance_double(Rex::Proto::Http::Packet::Header)
      allow(headers).to receive(:to_s).and_return(raw_headers)
      instance_double(Rex::Proto::Http::Response, headers: headers)
    end

    it 'returns true when /login/ sets a velocloud.* cookie' do
      raw = "Set-Cookie: velocloud.session=; Path=/\r\nServer: nginx\r\n"
      allow(subject).to receive(:send_request_cgi).and_return(http_response(raw))
      expect(subject.login_cookie_match?).to be(true)
    end

    it 'returns false when no velocloud cookie is set' do
      raw = "Set-Cookie: other=value\r\nServer: nginx\r\n"
      allow(subject).to receive(:send_request_cgi).and_return(http_response(raw))
      expect(subject.login_cookie_match?).to be(false)
    end

    it 'returns false when a non-cookie header contains velocloud. but Set-Cookie does not' do
      # Guards against a whole-headers false positive: a vendor-branded Server
      # line or similar must not misidentify an unrelated service as VeloCloud.
      raw = "Server: velocloud.custom\r\nSet-Cookie: other=value\r\n"
      allow(subject).to receive(:send_request_cgi).and_return(http_response(raw))
      expect(subject.login_cookie_match?).to be(false)
    end

    it 'returns false when the request fails' do
      allow(subject).to receive(:send_request_cgi).and_return(nil)
      expect(subject.login_cookie_match?).to be(false)
    end
  end
end
