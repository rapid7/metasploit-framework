# frozen_string_literal: true

RSpec.describe YARD::I18n::PotGenerator do
  def create_messages(messages)
    yard_messages = YARD::I18n::Messages.new
    add_messages(yard_messages, messages)
    yard_messages
  end

  def add_messages(yard_messages, messages)
    messages.each do |id, properties|
      yard_message = yard_messages.register(id)
      (properties[:locations] || []).each do |path, line|
        yard_message.add_location(path, line)
      end
      (properties[:comments] || []).each do |comment|
        yard_message.add_comment(comment)
      end
    end
  end

  before do
    @generator = YARD::I18n::PotGenerator.new("..")
  end

  describe "Generate" do
    it "generates the default header" do
      current_time = Time.parse("2011-11-20 22:17+0900")
      allow(@generator).to receive(:current_time).and_return(current_time)
      pot_creation_date = current_time.strftime("%Y-%m-%d %H:%M%z")
      expect(@generator.generate).to eq <<-eoh
# SOME DESCRIPTIVE TITLE.
# Copyright (C) YEAR THE PACKAGE'S COPYRIGHT HOLDER
# This file is distributed under the same license as the PACKAGE package.
# FIRST AUTHOR <EMAIL@ADDRESS>, YEAR.
#
#, fuzzy
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\\n"
"Report-Msgid-Bugs-To: \\n"
"POT-Creation-Date: #{pot_creation_date}\\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\\n"
"Language-Team: LANGUAGE <LL@li.org>\\n"
"Language: \\n"
"MIME-Version: 1.0\\n"
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"

eoh
    end

    it "generates messages in location order" do
      allow(@generator).to receive(:header).and_return("HEADER\n\n")
      messages = {
        "tag|see|Parser::SourceParser.parse" => {
          :locations => [["yard.rb", 14]],
          :comments => ["@see"]
        },
        "Parses a path or set of paths" => {
          :locations => [["yard.rb", 12], ["yard/parser/source_parser.rb", 83]],
          :comments => ["YARD.parse", "YARD::Parser::SourceParser.parse"]
        }
      }
      add_messages(@generator.messages, messages)
      expect(@generator.generate).to eq <<-'eoh'
HEADER

# YARD.parse
# YARD::Parser::SourceParser.parse
#: ../yard.rb:12
#: ../yard/parser/source_parser.rb:83
msgid "Parses a path or set of paths"
msgstr ""

# @see
#: ../yard.rb:14
msgid "tag|see|Parser::SourceParser.parse"
msgstr ""

eoh
    end
  end

  describe "Escape" do
    def generate_message_pot(message_id)
      pot = String.new("")
      message = YARD::I18n::Message.new(message_id)
      @generator.send(:generate_message, pot, message)
      pot
    end

    it "escapes <\\>" do
      expect(generate_message_pot("hello \\ world")).to eq <<-'eop'
msgid "hello \\ world"
msgstr ""

eop
    end

    it "escapes <\">" do
      expect(generate_message_pot("hello \" world")).to eq <<-'eop'
msgid "hello \" world"
msgstr ""

eop
    end

    it "escapes <\\n>" do
      expect(generate_message_pot("hello \n world")).to eq <<-'eop'
msgid "hello \n"
" world"
msgstr ""

eop
    end
  end

  describe "Object" do
    before do
      Registry.clear
      @yard = YARD::CodeObjects::ModuleObject.new(:root, :YARD)
    end

    it "extracts at docstring" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = "An alias to {Parser::SourceParser}'s parsing method"
      end
      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "An alias to {Parser::SourceParser}'s parsing method" => {
          :locations => [],
          :comments => ["YARD.parse"]
        }
      )
    end

    it "extracts at location" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = "An alias to {Parser::SourceParser}'s parsing method"
        o.files = [["yard.rb", 12]]
      end
      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "An alias to {Parser::SourceParser}'s parsing method" => {
          :locations => [["yard.rb", 13]],
          :comments => ["YARD.parse"]
        }
      )
    end

    it "extracts at tag name" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = "@see Parser::SourceParser.parse"
        o.files = [["yard.rb", 12]]
      end
      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "tag|see|Parser::SourceParser.parse" => {
          :locations => [["yard.rb", 12]],
          :comments => ["@see"]
        }
      )
    end

    it "extracts at tag text" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = <<-eod
@example Parse a glob of files
  YARD.parse('lib/**/*.rb')
eod
        o.files = [["yard.rb", 12]]
      end
      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "tag|example|Parse a glob of files" => {
          :locations => [["yard.rb", 12]],
          :comments => ["@example"]
        },
        "YARD.parse('lib/**/*.rb')" => {
          :locations => [["yard.rb", 12]],
          :comments => ["@example Parse a glob of files"]
        }
      )
    end

    it "extracts at tag types" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = <<-eod
@param [String, Array<String>] paths a path, glob, or list of paths to
  parse
eod
        o.files = [["yard.rb", 12]]
      end
      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "tag|param|paths" => {
          :locations => [["yard.rb", 12]],
          :comments => ["@param [String, Array<String>]"]
        },
        "a path, glob, or list of paths to\nparse" => {
          :locations => [["yard.rb", 12]],
          :comments => ["@param [String, Array<String>] paths"]
        }
      )
    end

    it "extracts at overload tag recursively" do
      object = YARD::CodeObjects::MethodObject.new(@yard, :parse, :module) do |o|
        o.docstring = <<-eod
@overload foo(i)
  docstring foo(i)
  @param [Integer] i integer parameter
eod
      end

      @generator.parse_objects([object])
      expect(@generator.messages).to eq create_messages(
        "tag|overload|foo" => {
          :locations => [],
          :comments => ["@overload"]
        },
        "docstring foo(i)" => {
          :locations => [],
          :comments => ["YARD.parse"]
        },
        "tag|param|i" => {
          :locations => [],
          :comments => ["@param [Integer]"]
        },
        "integer parameter" => {
          :locations => [],
          :comments => ["@param [Integer] i"]
        }
      )
    end
  end

  describe "File" do
    it "extracts at attribute" do
      path = "GettingStarted.md"
      text = <<-eor
# @title Getting Started Guide

# Getting Started with YARD
eor
      allow(File).to receive(:open).with(path).and_yield(StringIO.new(text))
      allow(File).to receive(:read).with(path).and_return(text)
      file = YARD::CodeObjects::ExtraFileObject.new(path)
      @generator.parse_files([file])
      expect(@generator.messages).to eq create_messages(
        "Getting Started Guide" => {
          :locations => [[path, 1]],
          :comments => ["title"]
        },
        "# Getting Started with YARD" => {
          :locations => [[path, 3]],
          :comments => []
        }
      )
    end

    it "extracts at paragraphs" do
      path = "README.md"
      paragraph1 = <<-eop.strip
Note that class methods must not be referred to with the "::" namespace
separator. Only modules, classes and constants should use "::".
eop
      paragraph2 = <<-eop.strip
You can also do lookups on any installed gems. Just make sure to build the
.yardoc databases for installed gems with:
eop
      text = <<-eot
#{paragraph1}

#{paragraph2}
eot
      allow(File).to receive(:open).with(path).and_yield(StringIO.new(text))
      allow(File).to receive(:read).with(path).and_return(text)
      file = YARD::CodeObjects::ExtraFileObject.new(path)
      @generator.parse_files([file])
      expect(@generator.messages).to eq create_messages(
        paragraph1 => {
          :locations => [[path, 1]],
          :comments => []
        },
        paragraph2 => {
          :locations => [[path, 4]],
          :comments => []
        }
      )
    end
  end
end
