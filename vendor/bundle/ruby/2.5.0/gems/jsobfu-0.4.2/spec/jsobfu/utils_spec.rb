require 'spec_helper'

describe JSObfu::Utils do
  # the number of iterations while testing randomness
  let(:n) { 50 }

  describe '#rand_text_alphanumeric' do
    let(:len) { 15 }

    # generates a new random string on every call
    def output; JSObfu::Utils.rand_text_alphanumeric(len); end

    it 'returns strings of length 15' do
      expect(n.times.map { output }.join.length).to be(n*len)
    end

    it 'returns strings in alpha charset' do
      expect(n.times.map { output }.join).to be_in_charset(described_class::ALPHANUMERIC_CHARSET)
    end
  end

  describe '#rand_text_alpha' do
    let(:len) { 15 }

    # generates a new random string on every call
    def output; JSObfu::Utils.rand_text_alpha(len); end

    it 'returns strings of length 15' do
      expect(n.times.map { output }.join.length).to be(n*len)
    end

    it 'returns strings in alpha charset' do
      expect(n.times.map { output }.join).to be_in_charset(described_class::ALPHA_CHARSET)
    end
  end

  describe '#rand_text' do
    let(:len) { 5 }
    let(:charset) { described_class::ALPHA_CHARSET }

    # generates a new random string on every call
    def output; described_class.rand_text(charset, len); end

    it 'returns strings of length 15' do
      expect(n.times.map { output }.join.length).to be(n*len)
    end

    it 'returns strings in the specified charset' do
      expect(n.times.map { output }.join).to be_in_charset(charset)
    end
  end

  describe '#to_hex' do
    let(:str) { '' }
    let(:delimiter) { "\\x" }
    subject(:hex_encoding) { described_class.to_hex(str, delimiter) }

    context 'when given the string "ABC"' do
      let(:str) { 'ABC' }
      it { should eq "\\x41\\x42\\x43" }

      context 'when the delimiter is "\\u00"' do
        let(:delimiter) { "\\u00" }
        it { should eq "\\u0041\\u0042\\u0043" }
      end
    end

    context 'when given an empty string' do
      let(:str) { '' }
      it { should eq '' }
    end
  end

  describe '#random_var_encoding' do
    let(:var_name) { 'ABCD' }
    let(:initial_value) { 123 }
    let(:preamble) { "var #{var_name} = #{initial_value}"}

    def encoded_var; described_class.random_var_encoding(var_name); end

    context 'when called multiple times on the same var' do
      it 'should evaluate to the same initial value' do
        10.times do
          js = "(function(){ #{preamble}; return #{encoded_var}; })()"
          expect(ExecJS.eval(js)).to eq initial_value
        end
      end
    end
  end

  describe '#safe_split' do
    let(:js_string) { "\\x66\\x67"*600 }
    let(:quote)     { '"' }
    let(:opts)      { { :quote => quote } }
    let(:parts) { 50.times.map { described_class.safe_split(js_string.dup, opts) } }

    describe 'quoting' do
      context 'when given a double-quote' do
        let(:quote) { '"' }
        it 'surrounds all the split strings with the same quote' do
          expect(parts.flatten.all? { |part| part.start_with?(quote) }).to be true
        end
      end

      context 'when given a single-quote' do
        let(:quote) { "'" }
        it 'surrounds all the split strings with the same quote' do
          expect(parts.flatten.all? { |part| part.start_with?(quote) }).to be true
        end
      end
    end

    describe 'splitting' do
      context 'when given a hex-escaped series of bytes' do
        let(:js_string) { "\\x66\\x67"*600 }

        it 'never splits in the middle of a hex escape' do
          expect(parts.flatten.all? { |part| part.start_with?('"\\') }).to be true
        end
      end

      context 'when given a unicode-escaped series of bytes' do
        let(:js_string) { "\\u0066\\u0067"*600 }

        it 'never splits in the middle of a unicode escape' do
          expect(parts.flatten.all? { |part| part.start_with?('"\\') }).to be true
        end
      end
    end
  end


  # surround the string in quotes
  def quote(str, q='"'); "#{q}#{str}#{q}" end

  describe '#transform_string' do
    context 'when given a string of length > MAX_STRING_CHUNK' do
      let(:js_string) { quote "ABC"*described_class::MAX_STRING_CHUNK }

      it 'calls itself recursively' do
        expect(described_class).to receive(:transform_string).at_least(2).times.and_call_original
        described_class.transform_string js_string, JSObfu::Scope.new
      end
    end

    context 'when given a string of length < MAX_STRING_CHUNK' do
      let(:js_string) { quote "A"*(described_class::MAX_STRING_CHUNK/2).to_i }

      it 'does not call itself recursively' do
        expect(described_class).to receive(:transform_string).once.and_call_original
        described_class.transform_string js_string, JSObfu::Scope.new
      end
    end
  end

end
