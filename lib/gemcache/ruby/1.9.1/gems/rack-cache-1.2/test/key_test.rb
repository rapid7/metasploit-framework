require "#{File.dirname(__FILE__)}/spec_setup"
require 'rack/cache/key'

describe 'A Rack::Cache::Key' do
  # Helper Methods =============================================================

  def mock_request(*args)
    uri, opts = args
    env = Rack::MockRequest.env_for(uri, opts || {})
    Rack::Cache::Request.new(env)
  end

  def new_key(request)
    Rack::Cache::Key.call(request)
  end

  it "sorts params" do
    request = mock_request('/test?z=last&a=first')
    new_key(request).should.include('a=first&z=last')
  end

  it "includes the scheme" do
    request = mock_request(
      '/test',
      'rack.url_scheme' => 'https',
      'HTTP_HOST' => 'www2.example.org'
    )
    new_key(request).should.include('https://')
  end

  it "includes host" do
    request = mock_request('/test', "HTTP_HOST" => 'www2.example.org')
    new_key(request).should.include('www2.example.org')
  end

  it "includes path" do
    request = mock_request('/test')
    new_key(request).should.include('/test')
  end

  it "sorts the query string by key/value after decoding" do
    request = mock_request('/test?x=q&a=b&%78=c')
    new_key(request).should.match(/\?a=b&x=c&x=q$/)
  end

  it "is in order of scheme, host, path, params" do
    request = mock_request('/test?x=y', "HTTP_HOST" => 'www2.example.org')
    new_key(request).should.equal "http://www2.example.org/test?x=y"
  end
end
