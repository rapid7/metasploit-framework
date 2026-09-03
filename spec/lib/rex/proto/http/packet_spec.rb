
require 'spec_helper'
require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'
require 'support/shared/examples/hash_with_insensitive_access'

RSpec.describe Rex::Proto::Http::Packet do
  describe '#parse with max_body_size' do
    subject(:request) { Rex::Proto::Http::Request.new }

    it 'rejects a declared body larger than the configured maximum before buffering it' do
      result = request.parse("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n", max_body_size: 4)

      expect(result).to eq(Rex::Proto::Http::Packet::ParseCode::Error)
      expect(request.error).to be_a(ArgumentError)
    end

    it 'rejects chunked bodies when their decoded size exceeds the configured maximum' do
      result = request.parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", max_body_size: 4)

      expect(result).to eq(Rex::Proto::Http::Packet::ParseCode::Error)
      expect(request.error).to be_a(ArgumentError)
    end
  end

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
