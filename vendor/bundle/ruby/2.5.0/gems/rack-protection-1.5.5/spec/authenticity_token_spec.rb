require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::AuthenticityToken do
  it_behaves_like "any rack application"

  it "denies post requests without any token" do
    post('/').should_not be_ok
  end

  it "accepts post requests with correct X-CSRF-Token header" do
    post('/', {}, 'rack.session' => {:csrf => "a"}, 'HTTP_X_CSRF_TOKEN' => "a")
    last_response.should be_ok
  end

  it "denies post requests with wrong X-CSRF-Token header" do
    post('/', {}, 'rack.session' => {:csrf => "a"}, 'HTTP_X_CSRF_TOKEN' => "b")
    last_response.should_not be_ok
  end

  it "accepts post form requests with correct authenticity_token field" do
    post('/', {"authenticity_token" => "a"}, 'rack.session' => {:csrf => "a"})
    last_response.should be_ok
  end

  it "denies post form requests with wrong authenticity_token field" do
    post('/', {"authenticity_token" => "a"}, 'rack.session' => {:csrf => "b"})
    last_response.should_not be_ok
  end

  it "prevents ajax requests without a valid token" do
    post('/', {}, "HTTP_X_REQUESTED_WITH" => "XMLHttpRequest").should_not be_ok
  end

  it "allows for a custom authenticity token param" do
    mock_app do
      use Rack::Protection::AuthenticityToken, :authenticity_param => 'csrf_param'
      run proc { |e| [200, {'Content-Type' => 'text/plain'}, ['hi']] }
    end

    post('/', {"csrf_param" => "a"}, 'rack.session' => {:csrf => "a"})
    last_response.should be_ok
  end

  it "sets a new csrf token for the session in env, even after a 'safe' request" do
    get('/', {}, {})
    env['rack.session'][:csrf].should_not be_nil
  end
end
