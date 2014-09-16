
require 'spec_helper'
require 'rex/proto/http/packet'

describe Rex::Proto::Http::Packet do
  it_behaves_like "hash with insensitive keys"

  describe "#parse" do
    let :body do
      "Super body"
    end
    subject do
      s = described_class.new
      s.parse packet_str

      s
    end
    context "with a request packet" do
      let :packet_str do
        "GET / HTTP/1.0\r\n" \
        "Foo: Bar\r\n" \
        "Content-Length: #{body.length}\r\n" \
        "\r\n" \
        "#{body}"
      end

      it "should have correct headers" do
        subject["foo"].should == "Bar"
        subject["Content-Length"].should == body.length.to_s
        subject.cmd_string.should == "GET / HTTP/1.0\r\n"
        subject.body.should == body
      end
    end

    context "with a response packet" do
      let :packet_str do
        "HTTP/1.0 200 OK\r\n" \
        "Foo: Bar\r\n" \
        "Content-Length: #{body.length}\r\n" \
        "\r\n" \
        "#{body}"
      end

      it "should have correct headers" do
        subject["foo"].should == "Bar"
        subject["Content-Length"].should == body.length.to_s
        subject.cmd_string.should == "HTTP/1.0 200 OK\r\n"
        subject.body.should == body
      end
    end

  end
end
