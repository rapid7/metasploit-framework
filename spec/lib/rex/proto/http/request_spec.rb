require 'spec_helper'

require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'

RSpec.describe Rex::Proto::Http::Request do
  describe '#parse' do
    it 'normalizes traversal in an incoming request before exposing its resource' do
      request = described_class.new
      result = request.parse("GET /a/b/../../payload HTTP/1.1\r\nHost: example\r\n\r\n")

      expect(result).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
      expect(request.resource).to eq('/payload')
      expect(request.relative_resource).to eq('/payload')
    end
  end

  describe '#body' do
    it 'uses the query string as the body for POST requests without explicit body bytes' do
      request = described_class.new('POST', '/api?foo=bar&baz=qux')

      expect(request.body).to eq('foo=bar&baz=qux')
      expect(request.to_s).to end_with("\r\n\r\nfoo=bar&baz=qux")
    end
  end

  describe '#normalize!' do
    subject(:request) { described_class.new }

    def normalize(str)
      copy = str.dup
      request.normalize!(copy)
      copy
    end

    [
      # [input, expected output]
      ['', ''],
      ['/', '/'],
      ['a', 'a'],
      ['a/', 'a/'],
      ['/a', '/a'],
      ['/a/', '/a/'],

      # multiple slashes collapse to one
      ['//', '/'],
      ['////', '/'],
      ['/a//b/', '/a/b/'],
      ['/a////b/', '/a/b/'],

      # self-referential "." directories collapse
      ['/./', '/'],
      ['/a/./b/', '/a/b/'],

      # "/word/../" directory traversal segments collapse
      ['/a/../', '/'],
      ['/a/b/../../', '/'],
      ['/a/b/../../../', '/../'],
      ['/a/./../', '/'],
      ['/a/b/./../c/../../', '/'],
      ['/a/b/c/../../../../../../', '/../../../'],
      ['/foo/bar/baz/../..', '/foo/bar/..'],

      # ".." is only eaten when flanked by slashes on both sides, and
      # only when the segment above it is made up entirely of \w+
      ['/a/..', '/a/..'],       # no trailing slash after ".."
      ['a/../b', 'a/../b'],     # no leading slash before "a"
      ['/../', '/../'],         # nothing eligible precedes it
      ['/../a/../', '/../'],
      ['/foo.bar/../', '/foo.bar/../'],  # dot is not a word character
      ['/foo-bar/../', '/foo-bar/../'],  # dash is not a word character
      ['/%2e%2e/../', '/%2e%2e/../'],    # percent-encoding is not \w+
      ['/_/../', '/'],
      ['/123/../', '/'],

      # deeply nested traversal fully collapses
      [('/a' * 50) + ('/..' * 50) + '/', '/'],
    ].each do |input, expected|
      it "normalizes #{input.inspect} to #{expected.inspect}" do
        expect(normalize(input)).to eq(expected)
      end
    end

    it 'returns 0 and leaves the string untouched when nothing changes' do
      str = '/a/b/c'
      expect(request.normalize!(str)).to eq(0)
      expect(str).to eq('/a/b/c')
    end

    it 'returns 1 and mutates the string in place when something changes' do
      str = '/a/../b/'
      expect(request.normalize!(str)).to eq(1)
      expect(str).to eq('/b/')
    end

    [
      ['/a/b/../../', '/'],
      ['/./././', '/'],
      ['/a/b/../../c/d/../../', '/'],
      ['/foo/././b/../../', '/']
    ].each do |input, expected|
      it "returns 1 when normalizing #{input.inspect}" do
        str = input.dup
        expect(request.normalize!(str)).to eq(1)
        expect(str).to eq(expected)
      end
    end

    it 'normalizes a small changed suffix after a long unchanged path' do
      prefix = '/a' * 10_000
      str = "#{prefix}/b/b/b/b/b/../../../../../"

      expect(request.normalize!(str)).to eq(1)
      expect(str).to eq("#{prefix}/")
    end

    it 'normalizes dense slashes followed by nested traversal' do
      str = ('/' * 128) + ('/a' * 30) + ('/..' * 30) + '/'

      expect(request.normalize!(str)).to eq(1)
      expect(str).to eq('/')
    end

    it 'raises FrozenError when given a frozen string that needs changes' do
      str = '/a/../'.freeze
      expect { request.normalize!(str) }.to raise_error(FrozenError)
    end

    it 'raises FrozenError even when the frozen string already needs no changes' do
      str = '/a/b/c'.freeze
      expect { request.normalize!(str) }.to raise_error(FrozenError)
    end

    it 'raises FrozenError on a frozen empty string' do
      str = ''.freeze
      expect { request.normalize!(str) }.to raise_error(FrozenError)
    end

    it 'raises NoMethodError when given nil' do
      expect { request.normalize!(nil) }.to raise_error(NoMethodError)
    end

    it 'does not mangle multibyte UTF-8 content in a retained segment while still collapsing traversal elsewhere' do
      # "café" is not \w+ (regex \w is ASCII-only), so it is retained as-is;
      # the "a/../" alongside it still collapses normally.
      str = '/café/a/../'
      expect(normalize(str)).to eq('/café/')
    end

    it 'does not mangle binary content in a retained segment while still collapsing traversal elsewhere' do
      str = "/\xFF\xFE/a/../bar/".dup.force_encoding('ASCII-8BIT')
      expect(normalize(str)).to eq("/\xFF\xFE/bar/".dup.force_encoding('ASCII-8BIT'))
    end

    it 'preserves multibyte content and encoding across multiple passes' do
      str = '/日本/a/b/../../'.encode(Encoding::Windows_31J)

      expect(request.normalize!(str)).to eq(1)
      expect(str).to eq('/日本/'.encode(Encoding::Windows_31J))
      expect(str.encoding).to eq(Encoding::Windows_31J)
    end

    it 'preserves the input encoding, including for an empty ASCII-8BIT string' do
      str = ''.dup.force_encoding('ASCII-8BIT')
      expect(request.normalize!(str)).to eq(0)
      expect(str.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'fully collapses a deeply nested traversal path' do
      pairs = 8000
      nested_path = ('/a' * pairs) + ('/..' * pairs) + '/'

      expect(request.normalize!(nested_path)).to eq(1)
      expect(nested_path).to eq('/')
    end

    it 'fully collapses deeply nested traversal after a multibyte segment' do
      nested_path = '/café/' + ('a/' * 8000) + ('../' * 8000)

      expect(request.normalize!(nested_path)).to eq(1)
      expect(nested_path).to eq('/café/')
    end
  end
end
