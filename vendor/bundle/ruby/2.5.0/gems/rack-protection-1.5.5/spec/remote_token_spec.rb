require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::RemoteToken do
  it_behaves_like "any rack application"

  it "accepts post requests with no referrer" do
    post('/').should be_ok
  end

  it "accepts post requests with a local referrer" do
    post('/', {}, 'HTTP_REFERER' => '/').should be_ok
  end

  it "denies post requests with a remote referrer and no token" do
    post('/', {}, 'HTTP_REFERER' => 'http://example.com/foo', 'HTTP_HOST' => 'example.org')
    last_response.should_not be_ok
  end

  it "accepts post requests with a remote referrer and correct X-CSRF-Token header" do
    post('/', {}, 'HTTP_REFERER' => 'http://example.com/foo', 'HTTP_HOST' => 'example.org',
      'rack.session' => {:csrf => "a"}, 'HTTP_X_CSRF_TOKEN' => "a")
    last_response.should be_ok
  end

  it "denies post requests with a remote referrer and wrong X-CSRF-Token header" do
    post('/', {}, 'HTTP_REFERER' => 'http://example.com/foo', 'HTTP_HOST' => 'example.org',
      'rack.session' => {:csrf => "a"}, 'HTTP_X_CSRF_TOKEN' => "b")
    last_response.should_not be_ok
  end

  it "accepts post form requests with a remote referrer and correct authenticity_token field" do
    post('/', {"authenticity_token" => "a"}, 'HTTP_REFERER' => 'http://example.com/foo',
      'HTTP_HOST' => 'example.org', 'rack.session' => {:csrf => "a"})
    last_response.should be_ok
  end

  it "denies post form requests with a remote referrer and wrong authenticity_token field" do
    post('/', {"authenticity_token" => "a"}, 'HTTP_REFERER' => 'http://example.com/foo',
      'HTTP_HOST' => 'example.org', 'rack.session' => {:csrf => "b"})
    last_response.should_not be_ok
  end
end
