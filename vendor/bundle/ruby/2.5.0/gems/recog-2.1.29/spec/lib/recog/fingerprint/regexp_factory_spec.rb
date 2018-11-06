
require 'recog/fingerprint/regexp_factory'

describe Recog::Fingerprint::RegexpFactory do

  describe 'FLAG_MAP' do
    subject { described_class::FLAG_MAP }

    it "should have the right number of flags" do
      expect(subject.size).to be 5
    end
  end

  describe '.build' do
    subject { described_class.build(pattern, options) }

    let(:pattern) { 'Apache/(\d+)' }
    let(:options) { [ 'REG_ICASE' ] }

    it { is_expected.to be_a(Regexp) }
    it { is_expected.to match('Apache/2') }

  end

  describe '.build_options' do
    subject { described_class.build_options(flags) }

    let(:flags) { [ ] }
    it { is_expected.to be_a(Fixnum) }

    context 'without any explicit flags' do
      let(:flags) { [ ] }
      specify "sets default flags" do
        expect(subject).to be Recog::Fingerprint::RegexpFactory::DEFAULT_FLAGS
      end
    end

    context 'with REG_ICASE' do
      let(:flags) { [ 'REG_ICASE' ] }
      specify "sets IGNORECASE" do
        expect(subject).to be (Recog::Fingerprint::RegexpFactory::DEFAULT_FLAGS | Regexp::IGNORECASE)
      end
    end

    context 'with REG_DOT_NEWLINE' do
      let(:flags) { [ 'REG_DOT_NEWLINE' ] }
      specify "sets MULTILINE" do
        expect(subject).to be (Recog::Fingerprint::RegexpFactory::DEFAULT_FLAGS | Regexp::MULTILINE)
      end
    end

    context 'with REG_LINE_ANY_CRLF' do
      let(:flags) { [ 'REG_LINE_ANY_CRLF' ] }
      specify "sets MULTILINE" do
        expect(subject).to be (Recog::Fingerprint::RegexpFactory::DEFAULT_FLAGS | Regexp::MULTILINE)
      end
    end

    context 'with multiple flags' do
      let(:flags) { [ 'REG_LINE_ANY_CRLF', 'REG_ICASE' ] }
      specify "sets correct flags" do
        expect(subject).to be (Recog::Fingerprint::RegexpFactory::DEFAULT_FLAGS | Regexp::MULTILINE | Regexp::IGNORECASE)
      end
    end

    context 'with invalid flags' do
      let(:flags) { %w(SYN ACK FIN) } # oh, wrong flags!
      specify 'raises and lists supported/unsupported flags' do
        expect { subject }.to raise_error(/SYN,ACK,FIN. Must be one of: .+/)
      end
    end
  end
end
