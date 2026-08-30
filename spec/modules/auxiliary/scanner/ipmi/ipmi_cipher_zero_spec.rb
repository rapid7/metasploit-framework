require 'rspec'

RSpec.describe 'IPMI Cipher Zero Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/ipmi/ipmi_cipher_zero'
    )
  end

  describe '#scanner_process' do
    # A complete, valid cipher-zero "session open" reply with error_code == 0.
    let(:valid_reply) do
      [0x06, 0x00, 0xff, 0x07, 0x06, Rex::Proto::IPMI::PAYLOAD_RMCPPLUSOPEN_REP & 0x3f].pack('C*') +
        [0x11111111].pack('V') +    # session id
        [0x22222222].pack('V') +    # session sequence
        [0x10].pack('v') +          # message length
        [0x00, 0x00].pack('C*') +   # ignored1, error_code (0 == vulnerable)
        [0x0000].pack('v') +        # ignored2
        ('CON1' + 'BMC1').b         # session data
    end

    # The various ways a real BMC can return something we can't parse. The 8-byte
    # and 12-byte truncations raise IOError ("data truncated"); the 1-byte case
    # raises EOFError, which is a subclass of IOError.
    [
      ['a 1-byte reply (EOFError)', "\x01".b],
      ['8 random bytes (IOError)', "\xde\xad\xbe\xef\x01\x02\x03\x04".b],
      ['a 12-byte truncated reply (IOError)', "\x06\x00\xff\x07\x06\x44\x11\x11\x11\x11\x22\x22".b]
    ].each do |label, data|
      it "ignores #{label} without raising" do
        expect { subject.scanner_process(data, '192.0.2.1', 623) }.not_to raise_error
      end
    end

    it 'still reports a valid reply that arrives after a malformed one' do
      subject.scanner_prescan(['192.0.2.1'])
      allow(subject).to receive(:report_vuln)

      expect(subject).to receive(:print_good).with(/VULNERABLE/)

      # A malformed straggler must not abort processing of the legitimate reply.
      subject.scanner_process("\xde\xad\xbe\xef\x01\x02\x03\x04".b, '192.0.2.1', 623)
      subject.scanner_process(valid_reply, '192.0.2.1', 623)
    end
  end
end
