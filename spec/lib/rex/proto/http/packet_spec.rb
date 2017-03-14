
require 'spec_helper'
require 'rex/proto/http/packet'

RSpec.describe Rex::Proto::Http::Packet do
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
        expect(subject["foo"]).to eq "Bar"
        expect(subject["Content-Length"]).to eq body.length.to_s
        expect(subject.cmd_string).to eq "GET / HTTP/1.0\r\n"
        expect(subject.body).to eq body
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
        expect(subject["foo"]).to eq "Bar"
        expect(subject["Content-Length"]).to eq body.length.to_s
        expect(subject.cmd_string).to eq "HTTP/1.0 200 OK\r\n"
        expect(subject.body).to eq body
      end
    end

  end
end
