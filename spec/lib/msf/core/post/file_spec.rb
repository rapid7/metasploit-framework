require 'rspec'

RSpec.describe Msf::Post::File do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin
    end
    klass.allocate
  end

  describe '#_can_echo?' do
    [
      # printable examples
      { input: '', expected: true },
      { input: 'hello world', expected: true },
      { input: "hello 'world'", expected: true },
      { input: "!@^&*()_+[]{}:|<>?,./;'\\[]1234567890-='", expected: true },

      # non-printable character examples, or breaking characters such as new line or quotes etc
      { input: "a\nb\nc", expected: false },
      { input: "\xff\x00", expected: false },
      { input: "\x00\x01\x02\x03\x04\x1f", expected: false },
      { input: "hello \"world\"", expected: false },
      { input: "🐂", expected: false },
      { input: "%APPDATA%", expected: false },
      { input: "$HOME", expected: false }
    ].each do |test|
      it "should return #{test[:expected]} for #{test[:input].inspect}" do
        expect(subject.send(:_can_echo?, test[:input])).to eql(test[:expected])
      end
    end
  end
end
