# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mime'

describe Rex::MIME::Header do

  let(:mime_headers_test) do
    <<-EOS
Content-Type: text/plain;
Content-Disposition: attachment; filename="test.txt"
    EOS
  end

  subject do
    described_class.new
  end

  describe "#initialize" do
    subject(:header_class) do
      described_class.allocate
    end

    it "returns an Array" do
      expect(header_class.send(:initialize)).to be_a(Array)
    end

    it "creates an empty headers array by default" do
      expect(header_class.send(:initialize)).to be_empty
    end

    it "populates headers array with data from argument" do
      header_class.send(:initialize, mime_headers_test)
      expect(header_class.headers.length).to be(2)
    end
  end

  describe "#add" do
    it "returns the added entry" do
      expect(subject.add('var', 'val')).to eq(['var', 'val'])
    end

    it "adds a new entry into the headers array" do
      subject.add('var', 'val')
      expect(subject.headers.length).to eq(1)
    end
  end

  describe "#set" do
    it "returns the set value" do
      expect(subject.set('var', 'val')).to eq('val')
    end

    it "modifies the header entry if it exists" do
      subject.add('var', 'val')
      subject.set('var', 'val2')
      expect(subject.headers.length).to eq(1)
      expect(subject.headers[0]).to eq(['var', 'val2'])
    end

    it "creates the header entry if doesn't exist" do
      subject.set('var2', 'val2')
      expect(subject.headers.length).to eq(1)
      expect(subject.headers[0]).to eq(['var2', 'val2'])
    end
  end

  describe "#remove" do
    it "doesn't remove any header if index doesn't exist" do
      subject.add('var', 'val')
      subject.remove(10000)
      expect(subject.headers.length).to eq(1)
    end

    it "doesn't remove any header if var name doesn't exist" do
      subject.add('var', 'val')
      subject.remove('var2')
      expect(subject.headers.length).to eq(1)
    end

    it "removes header entry if index exists" do
      subject.add('var', 'val')
      subject.remove(0)
      expect(subject.headers.length).to eq(0)
    end

    it "removes any header entry with var name" do
      subject.add('var', 'val')
      subject.add('var2', 'val2')
      subject.add('var', 'val3')
      subject.remove('var')
      expect(subject.headers.length).to eq(1)
    end
  end

  describe "#find" do
    it "returns nil if header index doesn't exist" do
      expect(subject.find(1)).to be_nil
    end

    it "returns nil if header var name doesn't exist" do
      expect(subject.find('var')).to be_nil
    end

    it "returns the header at index if exists" do
      subject.add('var', 'val')
      expect(subject.find(0)).to eq(['var', 'val'])
    end

    it "returns the first header with var name if exists" do
      subject.add('var', 'val')
      subject.add('var', 'val2')
      subject.add('var', 'val3')
      expect(subject.find('var')).to eq(['var', 'val'])
    end
  end

  describe "#to_s" do
    it "returns empty String if there aren't headers" do
      expect(subject.to_s).to be_empty
    end

    it "returns string with headers separated by \\r\\n sequences" do
      subject.add('var', 'val')
      subject.add('var', 'val2')
      subject.add('var3', 'val3')
      expect(subject.to_s).to eq("var: val\r\nvar: val2\r\nvar3: val3\r\n")
    end
  end

  describe "#parse" do
    let(:complex_header) do
      'Date: Wed,20 Aug 2014 08:45:38 -0500'
    end

    it "parses headers separated by lines" do
      subject.parse(mime_headers_test)
      expect(subject.headers.length).to eq(2)
    end

    it "parses headers names and values separated by :" do
      subject.parse(mime_headers_test)
      expect(subject.headers).to eq([['Content-Type', 'text/plain;'], ['Content-Disposition', 'attachment; filename="test.txt"']])
    end

    it "parses headers with ':' characters in the value" do
      subject.parse(complex_header)
      expect(subject.headers).to eq([['Date', 'Wed,20 Aug 2014 08:45:38 -0500']])
    end
  end
end
