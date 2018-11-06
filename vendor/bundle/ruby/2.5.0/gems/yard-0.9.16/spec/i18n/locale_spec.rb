# frozen_string_literal: true

RSpec.describe YARD::I18n::Locale do
  def locale(name)
    YARD::I18n::Locale.new(name)
  end

  before do
    @locale = locale("fr")
  end

  describe "#name" do
    it "returns name" do
      expect(locale("fr").name).to eq "fr"
    end
  end

  describe "#load" do
    it "returns false for nonexistent PO" do
      expect(File).to receive(:exist?).with('foo/fr.po').and_return(false)
      expect(@locale.load('foo')).to be false
    end

    have_gettext_gem = true
    if RUBY_VERSION < "1.9"
      begin
        require "gettext/tools/poparser"
      rescue LoadError
        have_gettext_gem = false
      end
    else
      begin
        require "gettext/po_parser"
      rescue LoadError
        begin
          require "gettext/tools/poparser"
        rescue LoadError
          have_gettext_gem = false
        end
      end
    end

    it "returns true for existent PO", :if => have_gettext_gem do
      data = <<-eop
msgid ""
msgstr ""
"Language: fr\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"

msgid "Hello"
msgstr "Bonjour"
eop
      parser = GetText::POParser.new
      expect(File).to receive(:exist?).with('foo/fr.po').and_return(true)
      expect(GetText::POParser).to receive(:new).and_return(parser)
      expect(parser).to receive(:parse_file) do |file, hash|
        expect(file).to eq 'foo/fr.po'
        parser.parse(String.new(data), hash)
      end
      expect(@locale.load('foo')).to be true
      expect(@locale.translate('Hello')).to eq "Bonjour"
    end
  end

  describe "#translate" do
    before do
      messages = @locale.instance_variable_get(:@messages)
      messages["Hello"] = "Bonjour"
    end

    it "returns translated string for existent string" do
      expect(@locale.translate("Hello")) == "Bonjour"
    end

    it "returns original string for nonexistent string" do
      expect(@locale.translate("nonexistent")) == "nonexistent"
    end
  end
end
