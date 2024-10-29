require 'postgres/postgres-pr/scram_sha_256'

RSpec.describe Msf::Db::PostgresPR::ScramSha256 do
  describe '#hi' do
    [
      { str: "a", salt: "c", iteration_count: 1, expected: "\xF5*3|\x9ALKB\xD1\x8D\x96d\xC1\x1D\v\xAEY^\xA8\xBB?o\x90\xE0\bE\xD5\xE1!\xA9={".b },
      { str: "a", salt: "c", iteration_count: 4096, expected: ")\xA4\x1E\xF6$Vn\x17~w\xFAA\xB4\x8C\xEFY\x83\x82}, 2\xCB\x02\x19Q\xB7\xADOR\xD9\xDC".b },
      { str: "pencil", salt: "\x00" * 16, iteration_count: 4096, expected: "\xB1q\x84\xD9\x8E\x0EG\xB2\"\xBD~\xB3-\xDABV?x\xC8'\xB7\xC8r\x9FJhG\xDAB%\xA0~".b },
      { str: "pencil", salt: "\x8C\xDDM\x0E\xDBa\xD5\xE4?\x8C\xF3V\xC9\xC9\x94V", iteration_count: 4096, expected: "\xB1?1\xF3\x86\xF5\"\x0F\xCB\xE3=\xE1\xFF(\xF0\x9BODB\xDD\xEF8\xCC\n\x16\x83\x1A&C\xA2\x86F".b },
    ].each do |test|
      it "returns the expected value for the test #{test}" do
        expect(subject.hi(test[:str], test[:salt], test[:iteration_count])).to eq(test[:expected])
      end
    end
  end

  describe '#gs2_header' do
    context 'when channel binding is false' do
      it 'returns a header without any channel bindings' do
        expect(subject.gs2_header(channel_binding: false)).to eq 'n,,'
      end
    end

    context 'when channel binding is true' do
      it 'returns a header without any channel bindings' do
        expect { subject.gs2_header(channel_binding: true) }.to raise_error NotImplementedError, 'Channel binding not implemented'
      end
    end
  end

  describe '#normalize' do
    [
      #
      # Tests from spec https://datatracker.ietf.org/doc/html/rfc4013#section-3
      #
      { str: "I\u00ADX", expected: "IX" },
      { str: "user", expected: "user" },
      { str: "USER", expected: "USER" },
      { str: "\u00AA", expected: "a" },
      { str: "\u2168", expected: "IX" },
      { str: "\u0007", error: /ASCII control characters/ },
      { str: "\u0627\u0031", error: /must start.*end with RandAL/ },

      #
      # Tests from saslprep implementation in Ruby gem https://github.com/ruby/net-imap/blob/92dabbb8959a7a1e02990968ee6a5f4f73dded17/test/net/imap/test_saslprep.rb#L37-L69
      #
      # some more prohibited codepoints
      { str: "\x7f", error: /ASCII control character/i },
      { str: "\ufff9", error: /Non-ASCII control character/i },
      { str: "\ue000", error: /private use.*C.3/i },
      { str: "\u{f0000}", error: /private use.*C.3/i },
      { str: "\u{100000}", error: /private use.*C.3/i },
      { str: "\ufffe", error: /Non-character code point.*C.4/i },
      { str: "\xed\xa0\x80", error: /invalid byte seq\w+ in UTF-8/i },
      { str: "\ufffd", error: /inapprop.* plain text.*C.6/i },
      { str: "\u2FFb", error: /inapprop.* canonical rep.*C.7/i },
      { str: "\u202c", error: /change display.*deprecate.*C.8/i },
      { str: "\u{e0001}", error: /tagging character/i },
      # some more invalid bidirectional characters
      { str: "\u0627abc\u0627", error: /must not contain.* Lcat/i },
      { str: "\u0627123", error: /must start.*end with RandAL/i },

      #
      # Arbitrary tests:
      #
      { str: "abc".force_encoding("ASCII"), expected: "abc".force_encoding("UTF-8") },
      { str: 'abcABC123!@£$%^&*()_+=[];l/.,?><|":]}{P+_) hello world', expected: 'abcABC123!@£$%^&*()_+=[];l/.,?><|":]}{P+_) hello world' }
    ].each do |test|
      it "returns the expected value for the test #{test}", skip: test[:skip] do
        if test[:error]
          expected_clazz = Msf::Db::PostgresPR::ScramSha256::NormalizeError
          expected_message = test[:error]
          expect { subject.normalize(test[:str]) }.to raise_error expected_clazz, expected_message
        else
          expect(subject.normalize(test[:str])).to eq(test[:expected])
        end
      end
    end
  end

  describe '#hmac' do
    [
      { key: "\x00\x01\x02\x03", message: "hello world", expected: "abc".b }
    ].each do |test|
      it "returns the expected value for the test #{test}" do
        expect(subject.hmac(test[:key], test[:message])).to eq("e\xA7\xB1r\xA9^9,\x90\x9Aey>FD\xF8\xCC\xD1\xDDH\xBB\x90\xDDU\xE5\x04\x05\xFA\xEC\xFC\x8Ew".b)
      end
    end
  end
end
