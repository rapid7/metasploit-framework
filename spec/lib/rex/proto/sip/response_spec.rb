# -*- coding: binary -*-

require 'rex/proto/sip/response'

describe 'Rex::Proto::SIP::Response parsing' do
  describe 'Parses vaild responses correctly' do
    specify do
      resp = 'SIP/1.0 123 Sure, OK'
      r = ::Rex::Proto::SIP::Response.parse(resp)
      r.status_line.should eq(resp)
      r.version.should eq('1.0')
      r.code.should eq('123')
      r.message.should eq('Sure, OK')
      r.headers.should be_nil
    end

    specify do
      resp = "SIP/2.0 200 OK\r\nFoo: bar\r\nBlah: 0\r\nFoO: blaf\r\n"
      r = ::Rex::Proto::SIP::Response.parse(resp)
      r.status_line.should eq('SIP/2.0 200 OK')
      r.version.should eq('2.0')
      r.code.should eq('200')
      r.message.should eq('OK')
      r.headers.should eq('Foo' => %w(bar), 'Blah' => %w(0), 'FoO' => %w(blaf))
      r.header('Foo').should eq %w(bar blaf)
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
