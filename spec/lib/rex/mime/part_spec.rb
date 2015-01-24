# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mime'

describe Rex::MIME::Part do

  subject do
    described_class.new
  end

  describe "#initialize" do
    subject(:part_class) do
      described_class.allocate
    end

    it "initializes the Rex::MIME::Header object" do
      part_class.send(:initialize)
      expect(part_class.header).to be_a(Rex::MIME::Header)
    end

    it "initializes the Rex::MIME::Header with an empty array of headers" do
      part_class.send(:initialize)
      expect(part_class.header.headers).to be_empty
    end

    it "Initializes content with an empty String" do
      part_class.send(:initialize)
      expect(part_class.content).to be_empty
    end
  end

  describe "#transfer_encoding" do
    it "returns nil if the part hasn't a Content-Transfer-Encoding header" do
      expect(subject.transfer_encoding).to be_nil
    end

    it "returns the transfer encoding value if a Content-Transfer-Encoding header exists" do
      subject.header.add('Content-Transfer-Encoding', 'base64')
      expect(subject.transfer_encoding).to eq('base64')
    end
  end

  describe "#binary_content?" do
    it "returns false if transfer encoding isn't defined" do
      expect(subject.binary_content?).to be_falsey
    end

    it "returns false if transfer encoding isn't binary" do
      subject.header.add('Content-Transfer-Encoding', 'base64')
      expect(subject.binary_content?).to be_falsey
    end

    it "returns true if transfer encoding is binary" do
      subject.header.add('Content-Transfer-Encoding', 'binary')
      expect(subject.binary_content?).to be_truthy
    end
  end

  describe "#content_encoded" do
    let(:content_test) do
      "\rTest1\n"
    end

    it "returns the exact content if transfer encoding is binary" do
      subject.header.add('Content-Transfer-Encoding', 'binary')
      subject.content = content_test
      expect(subject.content_encoded).to eq(content_test)
    end

    it "returns the content crlf encoded if transfer encoding isn't binary" do
      subject.content = content_test
      expect(subject.content_encoded).to eq("Test1\r\n")
    end
  end

  describe "#to_s" do
    it "returns headers and content separated by two \\r\\n sequences" do
      subject.header.add('var', 'val')
      subject.content = 'content'
      expect(subject.to_s).to eq("var: val\r\n\r\ncontent\r\n")
    end

    it "returns two \\r\\n sequences if part is empty" do
      expect(subject.to_s).to eq("\r\n\r\n")
    end

    it "ends with \\r\\n sequence" do
      expect(subject.to_s).to end_with("\r\n")
    end
  end
end
