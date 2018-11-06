# frozen_string_literal: true

# described_in_docs String, '#camelcase'
# described_in_docs String, '#underscore'

RSpec.describe String do
  describe "#shell_split" do
    it "splits simple non-quoted text" do
      expect("a b c".shell_split).to eq %w(a b c)
    end

    it "splits double quoted text into single token" do
      expect('a "b c d" e'.shell_split).to eq ["a", "b c d", "e"]
    end

    it "splits single quoted text into single token" do
      expect("a 'b c d' e".shell_split).to eq ["a", "b c d", "e"]
    end

    it "handles escaped quotations in quotes" do
      expect("'a \\' b'".shell_split).to eq ["a ' b"]
    end

    it "handles escaped quotations outside quotes" do
      expect("\\'a 'b'".shell_split).to eq %w('a b)
    end

    it "handles escaped backslash" do
      expect("\\\\'a b c'".shell_split).to eq ['\a b c']
    end

    it "handles any whitespace as space" do
      text = "foo\tbar\nbaz\r\nfoo2 bar2"
      expect(text.shell_split).to eq %w(foo bar baz foo2 bar2)
    end

    it "handles complex input" do
      text = "hello \\\"world \"1 2\\\" 3\" a 'b \"\\\\\\'' c"
      expect(text.shell_split).to eq ["hello", "\"world", "1 2\" 3", "a", "b \"\\'", "c"]
    end
  end
end
