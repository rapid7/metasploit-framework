
require 'spec_helper'
require 'rex/proto/http/packet/header'

RSpec.describe Rex::Proto::Http::Packet::Header do

  it_behaves_like "hash with insensitive keys"

  let :original_str do
    "POST /foo HTTP/1.0\r\n" \
    "Content-Length: 0\r\n" \
    "Foo: Bar\r\n" \
    "Bar: Baz\r\n" \
    "Combine-me: one\r\n" \
    "Combine-me: two\r\n" \
    "\r\n"
  end

  describe "#from_s" do
    subject(:headers) do
      h = described_class.new
      h.from_s(original_str)
      h
    end

    it "should create keys and values for each header" do
      expect(headers['Foo']).to eq "Bar"
      expect(headers['Content-Length']).to eq "0"
    end

    it "should combine headers" do
      expect(headers['Combine-me']).to eq "one, two"
    end

    context "with folding" do
      let :original_str do
        "POST /foo HTTP/1.0\r\n" \
        "Spaces:\r\n" \
        " Bar\r\n" \
        "Tabs:\r\n" \
        "\tBar\r\n" \
        "\r\n"
      end
      it "should recognize spaces" do
        expect(headers['Spaces']).to eq "Bar"
      end
      it "should recognize tabs" do
        expect(headers['Tabs']).to eq "Bar"
      end
    end

  end

  describe "#to_s" do
    subject(:header_string) do
      h = described_class.new
      h.from_s(original_str)
      h.to_s
    end

    context "without combining" do
      let :original_str do
        "POST /foo HTTP/1.0\r\n" \
        "Foo: Bar\r\n" \
        "Bar: Baz\r\n" \
        "\r\n"
      end

      it "should return the same string" do
        expect(header_string).to eq original_str
      end
    end
    context "with combining" do
      let :original_str do
        "POST /foo HTTP/1.0\r\n" \
        "Foo: Bar\r\n" \
        "Foo: Baz\r\n" \
        "Foo: Bab\r\n" \
        "\r\n"
      end
      it "should produce an equivalent string" do
        #pending "who knows"
        combined = "Foo: Bar, Baz, Bab\r\n\r\n"
        expect(header_string).to eq combined
      end
    end
  end

end
