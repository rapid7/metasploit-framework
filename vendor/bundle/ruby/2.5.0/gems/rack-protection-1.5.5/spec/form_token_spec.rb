require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::FormToken do
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

  it "accepts ajax requests without a valid token" do
    post('/', {}, "HTTP_X_REQUESTED_WITH" => "XMLHttpRequest").should be_ok
  end
end
