# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::ExtraFileObject do
  describe "#initialize" do
    it "attempts to read contents from filesystem if contents=nil" do
      expect(File).to receive(:read).with('file.txt').and_return('')
      ExtraFileObject.new('file.txt')
    end

    it "raises Errno::ENOENT if contents=nil and file does not exist" do
      expect { ExtraFileObject.new('file.txt') }.to raise_error(Errno::ENOENT)
    end

    it "does not attempt to read from disk if contents are provided" do
      # TODO: no assertions here!
      ExtraFileObject.new('file.txt', 'CONTENTS')
    end

    it "sets filename to filename" do
      file = ExtraFileObject.new('a/b/c/file.txt', 'CONTENTS')
      expect(file.filename).to eq "a/b/c/file.txt"
    end

    it "parses out attributes at top of the file" do
      file = ExtraFileObject.new('file.txt', "# @title X\n# @some_attribute Y\nFOO BAR")
      expect(file.attributes[:title]).to eq "X"
      expect(file.attributes[:some_attribute]).to eq "Y"
      expect(file.contents).to eq "FOO BAR"
    end

    it "allows whitespace prior to '#' marker when parsing attributes" do
      file = ExtraFileObject.new('file.txt', " \t # @title X\nFOO BAR")
      expect(file.attributes[:title]).to eq "X"
      expect(file.contents).to eq "FOO BAR"
    end

    it "allows the attributes section to be wrapped in an HTML comment" do
      file = ExtraFileObject.new('file.txt', "<!--\n# @title X\n-->\nFOO BAR")
      expect(file.attributes[:title]).to eq "X"
      expect(file.contents).to eq "FOO BAR"
    end

    it "allows whitespace around ignored HTML comment" do
      file = ExtraFileObject.new('file.txt', " \t <!-- \n# @title X\n \t --> \nFOO BAR")
      expect(file.attributes[:title]).to eq "X"
      expect(file.contents).to eq "FOO BAR"
    end

    it "parses out old-style #!markup shebang format" do
      file = ExtraFileObject.new('file.txt', "#!foobar\nHello")
      expect(file.attributes[:markup]).to eq "foobar"
    end

    it "does not parse old-style #!markup if any whitespace is found" do
      file = ExtraFileObject.new('file.txt', " #!foobar\nHello")
      expect(file.attributes[:markup]).to be nil
      expect(file.contents).to eq " #!foobar\nHello"
    end

    it "does not parse out attributes if there are newlines prior to attributes" do
      file = ExtraFileObject.new('file.txt', "\n# @title\nFOO BAR")
      expect(file.attributes).to be_empty
      expect(file.contents).to eq "\n# @title\nFOO BAR"
    end

    it "sets contents to data after attributes" do
      file = ExtraFileObject.new('file.txt', "# @title\nFOO BAR")
      expect(file.contents).to eq "FOO BAR"
    end

    it "preserves newlines" do
      file = ExtraFileObject.new('file.txt', "FOO\r\nBAR\nBAZ")
      expect(file.contents).to eq "FOO\r\nBAR\nBAZ"
    end

    it "does not include newlines in attribute data" do
      file = ExtraFileObject.new('file.txt', "# @title FooBar\r\nHello world")
      expect(file.attributes[:title]).to eq "FooBar"
    end

    it "forces encoding to @encoding attribute if present" do
      expect(log).not_to receive(:warn)
      data = String.new("# @encoding sjis\nFOO")
      data.force_encoding('binary')
      file = ExtraFileObject.new('file.txt', data)
      expect(['Shift_JIS', 'Windows-31J']).to include(file.contents.encoding.to_s)
    end if YARD.ruby19?

    it "warns if @encoding is invalid" do
      expect(log).to receive(:warn).with("Invalid encoding `INVALID' in file.txt")
      data = String.new("# @encoding INVALID\nFOO")
      encoding = data.encoding
      file = ExtraFileObject.new('file.txt', data)
      expect(file.contents.encoding).to eq encoding
    end if YARD.ruby19?

    it "ignores encoding in 1.8.x (or encoding-unaware platforms)" do
      expect(log).not_to receive(:warn)
      ExtraFileObject.new('file.txt', "# @encoding INVALID\nFOO")
    end if YARD.ruby18?

    it "attempts to re-parse data as 8-bit ascii if parsing fails" do
      expect(log).not_to receive(:warn)
      str, out = *([String.new("\xB0")] * 2)
      if str.respond_to?(:force_encoding)
        str.force_encoding('utf-8')
        out.force_encoding('binary')
      end
      file = ExtraFileObject.new('file.txt', str)
      expect(file.contents).to eq out
    end
  end

  describe "#name" do
    it "returns basename (not extension) of filename" do
      file = ExtraFileObject.new('file.txt', '')
      expect(file.name).to eq 'file'
    end
  end

  describe "#title" do
    it "returns @title attribute if present" do
      file = ExtraFileObject.new('file.txt', '# @title FOO')
      expect(file.title).to eq 'FOO'
    end

    it "returns #name if no @title attribute exists" do
      file = ExtraFileObject.new('file.txt', '')
      expect(file.title).to eq 'file'
    end
  end

  describe "#locale=" do
    it "translates contents" do
      file = ExtraFileObject.new('file.txt', 'Hello')
      file.locale = 'fr'
      fr_locale = I18n::Locale.new('fr')
      fr_messages = fr_locale.instance_variable_get(:@messages)
      fr_messages["Hello"] = 'Bonjour'
      expect(Registry).to receive(:locale).with('fr').and_return(fr_locale)
      expect(file.contents).to eq 'Bonjour'
    end
  end

  describe "#==" do
    it "defines equality based on filename alone" do
      file1 = ExtraFileObject.new('file.txt', 'A')
      file2 = ExtraFileObject.new('file.txt', 'B')
      expect(file1).to eq file2
      expect(file1).to eql file2
      expect(file1).to equal file2

      # Another way to test the equality interface
      a = [file1]
      a |= [file2]
      expect(a.size).to eq 1
    end
  end
end
