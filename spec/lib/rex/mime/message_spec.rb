# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mime'

describe Rex::MIME::Message do

  subject do
    described_class.new
  end

  describe "#initialize" do
    subject(:header_class) do
      described_class.allocate
    end

    it "creates a new Rex::MIME::Header" do
      header_class.send(:initialize)
      expect(header_class.header).to be_a(Rex::MIME::Header)
    end

    it "creates an empty array of parts" do
      header_class.send(:initialize)
      expect(header_class.parts).to be_empty
    end

    it "creates a random bound" do
      header_class.send(:initialize)
      expect(header_class.bound).to include('_Part_')
    end
  end

  describe "#to" do
    it "returns nil if To: header doesn't exist" do
      expect(subject.to).to be_nil
    end

    it "returns the To: header value if it exists" do
      subject.header.add('To', 'msfdev')
      expect(subject.to).to eq('msfdev')
    end
  end

  describe "#to=" do
    it "sets the To: header value" do
      subject.to = 'msfdev'
      expect(subject.to).to eq('msfdev')
    end

    it "returns the new To: header value" do
      expect(subject.to = 'msfdev').to eq('msfdev')
    end
  end


  describe "#from" do
    it "returns nil if From: header doesn't exist" do
      expect(subject.from).to be_nil
    end

    it "returns the From: header value if it exists" do
      subject.header.add('From', 'msfdev')
      expect(subject.from).to eq('msfdev')
    end
  end

  describe "#from=" do
    it "sets the From: header value" do
      subject.from = 'msfdev'
      expect(subject.from).to eq('msfdev')
    end

    it "returns the new From: header value" do
      expect(subject.from = 'msfdev').to eq('msfdev')
    end
  end

  describe "#subject" do
    it "returns nil if Subject: header doesn't exist" do
      expect(subject.subject).to be_nil
    end

    it "returns the Subject: header value if it exists" do
      subject.header.add('Subject', 'msfdev')
      expect(subject.subject).to eq('msfdev')
    end
  end

  describe "#subject=" do
    it "sets the Subject: header value" do
      subject.subject = 'msfdev'
      expect(subject.subject).to eq('msfdev')
    end

    it "returns the new Subject: header value" do
      expect(subject.subject = 'msfdev').to eq('msfdev')
    end
  end

  describe "#mime_defaults" do
    it "sets the MIME-Version header" do
      subject.mime_defaults
      expect(subject.header.find('MIME-Version')).to_not be_nil
    end

    it "sets the MIME-Version header to '1.0'" do
      subject.mime_defaults
      expect(subject.header.find('MIME-Version')).to eq(['MIME-Version', '1.0'])
    end

    it "sets the Content-Type header" do
      subject.mime_defaults
      expect(subject.header.find('Content-Type')).to_not be_nil
    end

    it "sets the Content-Type header to multipart/mixed" do
      subject.mime_defaults
      expect(subject.header.find('Content-Type')[1]).to include('multipart/mixed')
    end

    it "sets the Subject header" do
      subject.mime_defaults
      expect(subject.header.find('Subject')).to_not be_nil
    end

    it "sets the Subject header to empty string" do
      subject.mime_defaults
      expect(subject.header.find('Subject')).to eq(['Subject', ''])
    end

    it "sets the Message-ID header" do
      subject.mime_defaults
      expect(subject.header.find('Message-ID')).to_not be_nil
    end

    it "sets the From header" do
      subject.mime_defaults
      expect(subject.header.find('From')).to_not be_nil
    end

    it "sets the From header to empty string" do
      subject.mime_defaults
      expect(subject.header.find('From')).to eq(['From', ''])
    end

    it "sets the To header" do
      subject.mime_defaults
      expect(subject.header.find('To')).to_not be_nil
    end

    it "sets the To header to empty string" do
      subject.mime_defaults
      expect(subject.header.find('To')).to eq(['To', ''])
    end
  end

  describe "#add_part" do

  end

end
