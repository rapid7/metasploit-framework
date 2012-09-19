require 'rack/auth/basic'
require 'rack/lint'
require 'rack/mock'

describe Rack::Auth::Basic do
  def realm
    'WallysWorld'
  end

  def unprotected_app
    Rack::Lint.new lambda { |env|
      [ 200, {'Content-Type' => 'text/plain'}, ["Hi #{env['REMOTE_USER']}"] ]
    }
  end

  def protected_app
    app = Rack::Auth::Basic.new(unprotected_app) { |username, password| 'Boss' == username }
    app.realm = realm
    app
  end

  before do
    @request = Rack::MockRequest.new(protected_app)
  end

  def request_with_basic_auth(username, password, &block)
    request 'HTTP_AUTHORIZATION' => 'Basic ' + ["#{username}:#{password}"].pack("m*"), &block
  end

  def request(headers = {})
    yield @request.get('/', headers)
  end

  def assert_basic_auth_challenge(response)
    response.should.be.a.client_error
    response.status.should.equal 401
    response.should.include 'WWW-Authenticate'
    response.headers['WWW-Authenticate'].should =~ /Basic realm="#{Regexp.escape(realm)}"/
    response.body.should.be.empty
  end

  should 'challenge correctly when no credentials are specified' do
    request do |response|
      assert_basic_auth_challenge response
    end
  end

  should 'rechallenge if incorrect credentials are specified' do
    request_with_basic_auth 'joe', 'password' do |response|
      assert_basic_auth_challenge response
    end
  end

  should 'return application output if correct credentials are specified' do
    request_with_basic_auth 'Boss', 'password' do |response|
      response.status.should.equal 200
      response.body.to_s.should.equal 'Hi Boss'
    end
  end

  should 'return 400 Bad Request if different auth scheme used' do
    request 'HTTP_AUTHORIZATION' => 'Digest params' do |response|
      response.should.be.a.client_error
      response.status.should.equal 400
      response.should.not.include 'WWW-Authenticate'
    end
  end

  it 'takes realm as optional constructor arg' do
    app = Rack::Auth::Basic.new(unprotected_app, realm) { true }
    realm.should == app.realm
  end
end
