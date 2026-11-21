
require 'spec_helper'

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

RSpec.describe Rex::Proto::Http::Packet, 'body byte length' do
  let(:body) { [0x96ea, 0x1f600].pack('U*') }
  let(:response) do
    Rex::Proto::Http::Response.new(200).tap { |packet| packet.body = body }
  end

  it 'advertises seven octets for the two-character UTF-8 body' do
    expect(response.to_s).to include("Content-Length: 7\r\n")
  end

  it 'round trips the complete UTF-8 body through the binary network parser' do
    parsed = Rex::Proto::Http::Response.new
    parsed.parse(response.to_s.b)
    expect(parsed.body.b).to eq(body.b)
  end

  context 'with binary data' do
    let(:body) { [0, 255].pack('C*') }

    it 'preserves the existing byte length' do
      expect(response.to_s).to include("Content-Length: 2\r\n")
    end
  end

  context 'with gzip compression' do
    before { response.compress = 'gzip' }

    it 'counts the compressed bytes actually emitted' do
      _, content = response.to_s.split("\r\n\r\n", 2)
      expect(response.headers['Content-Length'].to_i).to eq(content.bytesize)
    end
  end

  context 'with automatic length disabled' do
    before do
      response.auto_cl = false
      response['Content-Length'] = 27
    end

    it 'preserves the explicit header' do
      expect(response.to_s).to include("Content-Length: 27\r\n")
    end
  end
end
