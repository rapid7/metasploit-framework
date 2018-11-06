require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::IPSpoofing do
  it_behaves_like "any rack application"

  it 'accepts requests without X-Forward-For header' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4', 'HTTP_X_REAL_IP' => '4.3.2.1')
    last_response.should be_ok
  end

  it 'accepts requests with proper X-Forward-For header' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4',
      'HTTP_X_FORWARDED_FOR' => '192.168.1.20, 1.2.3.4, 127.0.0.1')
    last_response.should be_ok
  end

  it 'denies requests where the client spoofs X-Forward-For but not the IP' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.4', 'HTTP_X_FORWARDED_FOR' => '1.2.3.5')
    last_response.should_not be_ok
  end

  it 'denies requests where the client spoofs the IP but not X-Forward-For' do
    get('/', {}, 'HTTP_CLIENT_IP' => '1.2.3.5',
      'HTTP_X_FORWARDED_FOR' => '192.168.1.20, 1.2.3.4, 127.0.0.1')
    last_response.should_not be_ok
  end

  it 'denies requests where IP and X-Forward-For are spoofed but not X-Real-IP' do
    get('/', {},
      'HTTP_CLIENT_IP'       => '1.2.3.5',
      'HTTP_X_FORWARDED_FOR' => '1.2.3.5',
      'HTTP_X_REAL_IP'       => '1.2.3.4')
    last_response.should_not be_ok
  end
end
