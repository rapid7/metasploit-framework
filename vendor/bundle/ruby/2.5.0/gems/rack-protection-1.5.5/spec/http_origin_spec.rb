require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::HttpOrigin do
  it_behaves_like "any rack application"

  before(:each) do
    mock_app do
      use Rack::Protection::HttpOrigin
      run DummyApp
    end
  end

  %w(GET HEAD POST PUT DELETE).each do |method|
    it "accepts #{method} requests with no Origin" do
      send(method.downcase, '/').should be_ok
    end
  end

  %w(GET HEAD).each do |method|
    it "accepts #{method} requests with non-whitelisted Origin" do
      send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://malicious.com').should be_ok
    end
  end

  %w(POST PUT DELETE).each do |method|
    it "denies #{method} requests with non-whitelisted Origin" do
      send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://malicious.com').should_not be_ok
    end

    it "accepts #{method} requests with whitelisted Origin" do
      mock_app do
        use Rack::Protection::HttpOrigin, :origin_whitelist => ['http://www.friend.com']
        run DummyApp
      end
      send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://www.friend.com').should be_ok
    end
  end
end
