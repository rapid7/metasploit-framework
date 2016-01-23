# -*- coding: binary -*-

require 'rex/proto/sip/response'

RSpec.describe 'Rex::Proto::SIP::Response parsing' do
  describe 'Parses vaild responses correctly' do
    specify do
      resp = 'SIP/1.0 123 Sure, OK'
      r = ::Rex::Proto::SIP::Response.parse(resp)
      expect(r.status_line).to eq(resp)
      expect(r.version).to eq('1.0')
      expect(r.code).to eq('123')
      expect(r.message).to eq('Sure, OK')
      expect(r.headers).to be_nil
    end

    specify do
      resp = "SIP/2.0 200 OK\r\nFoo: bar\r\nBlah: 0\r\nFoO: blaf\r\n"
      r = ::Rex::Proto::SIP::Response.parse(resp)
      expect(r.status_line).to eq('SIP/2.0 200 OK')
      expect(r.version).to eq('2.0')
      expect(r.code).to eq('200')
      expect(r.message).to eq('OK')
      expect(r.headers).to eq('Foo' => %w(bar), 'Blah' => %w(0), 'FoO' => %w(blaf))
      expect(r.header('Foo')).to eq %w(bar blaf)
    end
  end

  describe 'Parses invalid responses correctly' do
    [
      '',
      'aldkjfakdjfasdf',
      'SIP/foo 200 OK',
      'SIP/2.0 foo OK'
    ].each do |r|
      it 'Should fail to parse an invalid response' do
        expect { ::Rex::Proto::SIP::Response.parse(r) }.to raise_error(ArgumentError, /status/)
      end
    end
  end
end
