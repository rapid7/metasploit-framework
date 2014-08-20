# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mime'
require 'rex/text'

describe Rex::MIME::Message do

  subject do
    described_class.new
  end

  let(:raw_message) do
    message = "MIME-Version: 1.0\r\n"
    message << "Content-Type: multipart/mixed; boundary=\"_Part_12_3195573780_381739540\"\r\n"
    message << "Subject: Pull Request\r\n"
    message << "Date: Wed,20 Aug 2014 08:45:38 -0500\r\n"
    message << "Message-ID: <WRobqc7gEyQVIQwEkLS7FN3ZNhS1Xj9pU2szC24rggMg@tqUqGjjSLEvssbwm>\r\n"
    message << "From: contributor@msfdev.int\r\n"
    message << "To: msfdev@msfdev.int\r\n"
    message << "\r\n"
    message << "--_Part_12_3195573780_381739540\r\n"
    message << "Content-Disposition: inline; filename=\"content\"\r\n"
    message << "Content-Type: application/octet-stream; name=\"content\"\r\n"
    message << "Content-Transfer-Encoding: base64\r\n"
    message << "\r\n"
    message << "Q29udGVudHM=\r\n"
    message << "\r\n"
    message << "--_Part_12_3195573780_381739540--\r\n"

    message
  end

  let(:regexp_mail) do
    regex = "MIME-Version: 1.0\r\n"
    regex << "Content-Type: multipart/mixed; boundary=\"_Part_.*\"\r\n"
    regex << "Subject: Pull Request\r\n"
    regex << "Date: .*\r\n"
    regex << "Message-ID: <.*@.*>\r\n"
    regex << "From: contributor@msfdev.int\r\n"
    regex << "To: msfdev@msfdev.int\r\n"
    regex << "\r\n"
    regex << "--_Part_.*\r\n"
    regex << "Content-Disposition: inline\r\n"
    regex << "Content-Type: text/plain\r\n"
    regex << "Content-Transfer-Encoding: base64\r\n"
    regex << "\r\n"
    regex << "Q29udGVudHM=\r\n"
    regex << "\r\n"
    regex << "--_Part_.*--\r\n"

    Regexp.new(regex)
  end

  let(:regexp_web) do
    regex = "\r\n"
    regex << "--_Part_.*\r\n"
    regex << "Content-Disposition: form-data; name=\"action\"\r\n"
    regex << "\r\n"
    regex << "save\r\n"
    regex << "--_Part_.*\r\n"
    regex << "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
    regex << "Content-Type: application/octet-stream\r\n"
    regex << "\r\n"
    regex << "Contents\r\n"
    regex << "--_Part_.*\r\n"
    regex << "Content-Disposition: form-data; name=\"title\"\r\n"
    regex << "\r\n"
    regex << "Title\r\n"
    regex << "--_Part_.*--\r\n"

    Regexp.new(regex)
  end

  describe "#initialize" do
    subject(:message_class) do
      described_class.allocate
    end

    it "creates a new Rex::MIME::Header" do
      message_class.send(:initialize)
      expect(message_class.header).to be_a(Rex::MIME::Header)
    end

    it "creates an empty array of parts" do
      message_class.send(:initialize)
      expect(message_class.parts).to be_empty
    end

    it "creates a random bound" do
      message_class.send(:initialize)
      expect(message_class.bound).to include('_Part_')
    end

    it "allows to populate headers from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.headers.length).to eq(7)
    end

    it "allows to create a MIME-Version header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('MIME-Version')).to eq(['MIME-Version', '1.0'])
    end

    it "allows to create a Content-Type header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('Content-Type')).to eq(['Content-Type', "multipart/mixed; boundary=\"_Part_12_3195573780_381739540\""])
    end

    it "allows to create a Subject header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('Subject')).to eq(['Subject', 'Pull Request'])
    end

    it "allows to create a Date header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('Date')).to eq(['Date', 'Wed,20 Aug 2014 08:45:38 -0500'])
    end

    it "allows to create a Message-ID header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('Message-ID')).to eq(['Message-ID', '<WRobqc7gEyQVIQwEkLS7FN3ZNhS1Xj9pU2szC24rggMg@tqUqGjjSLEvssbwm>'])
    end

    it "allows to create a From header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('From')).to eq(['From', 'contributor@msfdev.int'])
    end

    it "allows to create a To header from argument" do
      message_class.send(:initialize, raw_message)
      expect(message_class.header.find('To')).to eq(['To', 'msfdev@msfdev.int'])
    end

    it "allows to populate parts from argument" do
      message_class.send(:initialize, raw_message)
      p "#{message_class.parts.inspect}"
      expect(message_class.parts.length).to eq(1)
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
    it "returns the new part" do
      expect(subject.add_part).to be_a(Rex::MIME::Part)
    end

    it "sets Content-Type to text/plain by default" do
      part = subject.add_part
      expect(part.header.find('Content-Type')[1]).to eq('text/plain')
    end

    it "sets Content-Transfer-Encoding to 8bit by default" do
      part = subject.add_part
      expect(part.header.find('Content-Transfer-Encoding')[1]).to eq('8bit')
    end

    it "doesn't set Content-Disposition by default" do
      part = subject.add_part
      expect(part.header.find('Content-Disposition')).to be_nil
    end

    it "allows to set up Content-Type" do
      part = subject.add_part('', 'application/pdf')
      expect(part.header.find('Content-Type')[1]).to eq('application/pdf')
    end

    it "allows to set up Content-Transfer-Encoding" do
      part = subject.add_part('', 'application/pdf', 'binary')
      expect(part.header.find('Content-Transfer-Encoding')[1]).to eq('binary')
    end

    it "allows to set up Content-Disposition" do
      part = subject.add_part('', 'application/pdf', 'binary', 'attachment; filename="fname.ext"')
      expect(part.header.find('Content-Disposition')[1]).to eq('attachment; filename="fname.ext"')
    end

    it "allows to set up content" do
      part = subject.add_part('msfdev')
      expect(part.content).to eq('msfdev')
    end
  end

  describe "#add_part_attachment" do
    it "requires data argument" do
      expect { subject.add_part_attachment }.to raise_error(ArgumentError)
    end

    it "requires name argument" do
      expect { subject.add_part_attachment('data') }.to raise_error(ArgumentError)
    end

    it 'returns the new Rex::MIME::Part' do
      expect(subject.add_part_attachment('data', 'name')).to be_a(Rex::MIME::Part)
    end

    it 'encodes the part content with base64' do
      part = subject.add_part_attachment('data', 'name')
      expect(part.content).to eq(Rex::Text.encode_base64('data', "\r\n"))
    end

    it 'setup Content-Type as application/octet-stream' do
      part = subject.add_part_attachment('data', 'name')
      expect(part.header.find('Content-Type')[1]).to eq('application/octet-stream; name="name"')
    end

    it 'setup Content-Transfer-Encoding as base64' do
      part = subject.add_part_attachment('data', 'name')
      expect(part.header.find('Content-Transfer-Encoding')[1]).to eq('base64')
    end

    it 'setup Content-Disposition as attachment' do
      part = subject.add_part_attachment('data', 'name')
      expect(part.header.find('Content-Disposition')[1]).to eq('attachment; filename="name"')
    end
  end

  describe "#add_part_inline_attachment" do
    it "requires data argument" do
      expect { subject.add_part_inline_attachment }.to raise_error(ArgumentError)
    end

    it "requires name argument" do
      expect { subject.add_part_inline_attachment('data') }.to raise_error(ArgumentError)
    end

    it 'returns the new Rex::MIME::Part' do
      expect(subject.add_part_inline_attachment('data', 'name')).to be_a(Rex::MIME::Part)
    end

    it 'encodes the part content with base64' do
      part = subject.add_part_inline_attachment('data', 'name')
      expect(part.content).to eq(Rex::Text.encode_base64('data', "\r\n"))
    end

    it 'setup Content-Type as application/octet-stream' do
      part = subject.add_part_inline_attachment('data', 'name')
      expect(part.header.find('Content-Type')[1]).to eq('application/octet-stream; name="name"')
    end

    it 'setup Content-Transfer-Encoding as base64' do
      part = subject.add_part_inline_attachment('data', 'name')
      expect(part.header.find('Content-Transfer-Encoding')[1]).to eq('base64')
    end

    it 'setup Content-Disposition as attachment' do
      part = subject.add_part_inline_attachment('data', 'name')
      expect(part.header.find('Content-Disposition')[1]).to eq('inline; filename="name"')
    end
  end

  describe "#to_s" do
    it "returns \\r\\n if Rex::MIME::Message is empty" do
      expect(subject.to_s).to eq("\r\n")
    end

    it "generates valid MIME email messages" do
      subject.mime_defaults
      subject.from = "contributor@msfdev.int"
      subject.to = "msfdev@msfdev.int"
      subject.subject = "Pull Request"
      subject.add_part(Rex::Text.encode_base64("Contents", "\r\n"), "text/plain", "base64", "inline")
      expect(regexp_mail.match(subject.to_s)).to_not be_nil
    end

    it "generates valid MIME web forms" do
      subject.add_part("save", nil, nil, "form-data; name=\"action\"")
      subject.add_part("Contents", "application/octet-stream", nil, "form-data; name=\"file\"; filename=\"test.txt\"")
      subject.add_part("Title", nil, nil, "form-data; name=\"title\"")
      expect(regexp_web.match(subject.to_s)).to_not be_nil
    end
  end

end
