# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_examples "datastore" do
  it "should have options" do
    expect(subject["foo"]).to eq "bar"
    expect(subject["fizz"]).to eq "buzz"
  end
  it "should have case-insensitive keys" do
    # Sorted by gray code, just for fun
    expect(subject["foo"]).to eq "bar"
    expect(subject["Foo"]).to eq "bar"
    expect(subject["FOo"]).to eq "bar"
    expect(subject["fOo"]).to eq "bar"
    expect(subject["fOO"]).to eq "bar"
    expect(subject["FOO"]).to eq "bar"
    expect(subject["FoO"]).to eq "bar"
    expect(subject["foO"]).to eq "bar"
  end
  context "#to_h" do
    it "should return a Hash with correct values" do
      expect(subject.to_h).to eq({ "foo" => "bar", "fizz" => "buzz" })
    end
  end
  context "#delete" do
    it "should delete the specified case-insensitive key" do
      expect(subject.delete("foo")).to eq "bar"
      expect(subject.delete("Fizz")).to eq "buzz"
    end
  end
end

RSpec.describe Msf::DataStore do

  describe ".GLOBAL_OPTION_DEFINITIONS" do
    it "contains only OptBase subclass instances" do
      Msf::DataStore::GLOBAL_OPTION_DEFINITIONS.each_option do |_name, opt|
        expect(opt).to be_a(Msf::OptBase)
      end
    end

    it "defines the expected option types" do
      defs = Msf::DataStore::GLOBAL_OPTION_DEFINITIONS
      expect(defs['ConsoleLogging']).to be_a(Msf::OptBool)
      expect(defs['LogLevel']).to be_a(Msf::OptInt)
      expect(defs['MinimumRank']).to be_a(Msf::OptEnum)
      expect(defs['SessionLogging']).to be_a(Msf::OptBool)
      expect(defs['TimestampOutput']).to be_a(Msf::OptBool)
      expect(defs['VERBOSE']).to be_a(Msf::OptBool)
      expect(defs['SessionTlvLogging']).to be_a(Msf::OptSessionTlvLogging)
    end

    it "derives GLOBAL_KEYS with the same key names" do
      expected_keys = %w[
        ConsoleLogging
        LogLevel
        MinimumRank
        SessionLogging
        TimestampOutput
        VERBOSE
        Prompt
        PromptChar
        PromptTimeFormat
        MeterpreterPrompt
        SessionTlvLogging
      ]
      expect(Msf::DataStore::GLOBAL_KEYS).to match_array(expected_keys)
    end
  end

  describe "#import_option" do
    subject do
      s = described_class.new
      s.import_option("foo", "bar")
      s.import_option("fizz", "buzz")
      s
    end
    it_behaves_like "datastore"
  end

  describe "#import_options_from_hash" do
    subject do
      hash = { "foo" => "bar", "fizz" => "buzz" }
      s = described_class.new
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like "datastore"
  end

  describe "#import_options_from_s" do
    subject do
      str = "foo=bar fizz=buzz"
      s = described_class.new
      s.import_options_from_s(str)
      s
    end
    it_behaves_like "datastore"

    context "parsing corner cases" do
      it "should parse comma separated strings" do
        str = "foo=bar,fizz=buzz"
        subject.import_options_from_s(str)

        expect(subject).to have_key("foo")
        expect(subject["foo"]).to eql("bar")
        expect(subject).to have_key("fizz")
        expect(subject["fizz"]).to eql("buzz")
      end

      it "should parse options with nested equals" do
        str = "COMMAND=date --date=2023-01-01 --iso-8601=ns,SESSION=1"
        subject.import_options_from_s(str)

        expect(subject).to have_key("COMMAND")
        expect(subject["COMMAND"]).to eql("date --date=2023-01-01 --iso-8601=ns")
        expect(subject).to have_key("SESSION")
        expect(subject["SESSION"]).to eql("1")
      end
    end
  end

  describe "#from_file" do
    subject do
      ini_instance = double group?: true,
                            :[] => {
                              "foo" => "bar",
                              "fizz" => "buzz"
                            }
      ini_class = double from_file: ini_instance

      stub_const("Rex::Parser::Ini", ini_class)

      s = described_class.new
      s.from_file("path")
      s
    end

    it_behaves_like "datastore"

    context "normalizes values loaded from an INI config file" do
      subject do
        ds = described_class.new
        ds.import_options(Msf::DataStore::GLOBAL_OPTION_DEFINITIONS)
        ds
      end

      it "normalizes boolean and integer strings" do
        ini_instance = double group?: true,
                              :[] => {
                                "VERBOSE" => "true",
                                "ConsoleLogging" => "false",
                                "LogLevel" => "3"
                              }
        ini_class = double from_file: ini_instance
        stub_const("Rex::Parser::Ini", ini_class)

        subject.from_file("path")

        expect(subject['VERBOSE']).to eq true
        expect(subject['ConsoleLogging']).to eq false
        expect(subject['LogLevel']).to eq 3
      end
    end

    it "registers each option by name" do
      options = Msf::OptionContainer.new([
        Msf::OptBool.new('TestBool', [false, 'A bool', false]),
        Msf::OptInt.new('TestInt', [false, 'An int', 0]),
      ])
      subject.import_options(options)
      expect(subject.options['TestBool']).to be_a(Msf::OptBool)
      expect(subject.options['TestInt']).to be_a(Msf::OptInt)
    end

    it "normalizes values through registered options" do
      options = Msf::OptionContainer.new([Msf::OptBool.new('MyFlag', [false, 'A flag', false])])
      subject.import_options(options)
      subject['MyFlag'] = 'true'
      expect(subject['MyFlag']).to eq true
    end

    it "registers options from a standalone OptionContainer" do
      options = Msf::OptionContainer.new
      options.add_options([
        Msf::OptString.new('Foo', [false, 'A string', nil])
      ])
      subject.import_options(options)
      expect(subject.options['Foo']).to be_a(Msf::OptString)
    end
  end

end
