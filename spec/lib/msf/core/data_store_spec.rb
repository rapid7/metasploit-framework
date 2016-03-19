# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/data_store'

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
  end


end
