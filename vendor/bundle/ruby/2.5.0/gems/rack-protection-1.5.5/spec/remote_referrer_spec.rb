require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::RemoteReferrer do
  it_behaves_like "any rack application"

  it "accepts post requests with no referrer" do
    post('/').should be_ok
  end

  it "does not accept post requests with no referrer if allow_empty_referrer is false" do
    mock_app do
      use Rack::Protection::RemoteReferrer, :allow_empty_referrer => false
      run DummyApp
    end
    post('/').should_not be_ok
  end

  it "should allow post request with a relative referrer" do
    post('/', {}, 'HTTP_REFERER' => '/').should be_ok
  end

  it "accepts post requests with the same host in the referrer" do
    post('/', {}, 'HTTP_REFERER' => 'http://example.com/foo', 'HTTP_HOST' => 'example.com')
    last_response.should be_ok
  end

  it "denies post requests with a remote referrer" do
    post('/', {}, 'HTTP_REFERER' => 'http://example.com/foo', 'HTTP_HOST' => 'example.org')
    last_response.should_not be_ok
  end
end
