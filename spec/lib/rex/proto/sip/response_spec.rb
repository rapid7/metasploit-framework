# encoding: UTF-8

require 'rex/proto/sip/response'
include Rex::Proto::SIP

describe 'Rex::Proto::SIP::Response parsing' do
  describe 'Parses vaild responses correctly' do
    specify do
      r = Response.parse('SIP/1.0 123 Sure, OK')
      r.version.should eq('1.0')
      r.code.should eq('123')
      r.message.should eq('Sure, OK')
      r.headers.should be_nil
    end

    specify do
      r = Response.parse("SIP/2.0 200 OK\r\nFoo: bar\r\nBlah: 0\r\n")
      r.version.should eq('2.0')
      r.code.should eq('200')
      r.message.should eq('OK')
      r.headers.should eq('Foo' => %w(bar), 'Blah' => %w(0))
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
        expect { Response.parse(r) }.to raise_error(ArgumentError, /status/)
      end
    end
  end
end
