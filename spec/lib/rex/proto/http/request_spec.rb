require 'spec_helper'

require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'

RSpec.describe Rex::Proto::Http::Request do
  describe '#body' do
    it 'uses the query string as the body for POST requests without explicit body bytes' do
      request = described_class.new('POST', '/api?foo=bar&baz=qux')

      expect(request.body).to eq('foo=bar&baz=qux')
      expect(request.to_s).to end_with("\r\n\r\nfoo=bar&baz=qux")
    end
  end
end
