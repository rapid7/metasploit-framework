require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::FrameOptions do
  it_behaves_like "any rack application"

  it 'should set the X-Frame-Options' do
    get('/', {}, 'wants' => 'text/html').headers["X-Frame-Options"].should == "SAMEORIGIN"
  end

  it 'should not set the X-Frame-Options for other content types' do
    get('/', {}, 'wants' => 'text/foo').headers["X-Frame-Options"].should be_nil
  end

  it 'should allow changing the protection mode' do
    # I have no clue what other modes are available
    mock_app do
      use Rack::Protection::FrameOptions, :frame_options => :deny
      run DummyApp
    end

    get('/', {}, 'wants' => 'text/html').headers["X-Frame-Options"].should == "DENY"
  end


  it 'should allow changing the protection mode to a string' do
    # I have no clue what other modes are available
    mock_app do
      use Rack::Protection::FrameOptions, :frame_options => "ALLOW-FROM foo"
      run DummyApp
    end

    get('/', {}, 'wants' => 'text/html').headers["X-Frame-Options"].should == "ALLOW-FROM foo"
  end

  it 'should not override the header if already set' do
    mock_app with_headers("X-Frame-Options" => "allow")
    get('/', {}, 'wants' => 'text/html').headers["X-Frame-Options"].should == "allow"
  end
end
