require File.expand_path('../helper', __FILE__)
require 'stringio'

class RequestTest < Minitest::Test
  it 'responds to #user_agent' do
    request = Sinatra::Request.new({'HTTP_USER_AGENT' => 'Test'})
    assert request.respond_to?(:user_agent)
    assert_equal 'Test', request.user_agent
  end

  it 'parses POST params when Content-Type is form-dataish' do
    request = Sinatra::Request.new(
      'REQUEST_METHOD' => 'PUT',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
      'rack.input' => StringIO.new('foo=bar')
    )
    assert_equal 'bar', request.params['foo']
  end

  it 'is secure when the url scheme is https' do
    request = Sinatra::Request.new('rack.url_scheme' => 'https')
    assert request.secure?
  end

  it 'is not secure when the url scheme is http' do
    request = Sinatra::Request.new('rack.url_scheme' => 'http')
    assert !request.secure?
  end

  it 'respects X-Forwarded-Proto header for proxied SSL' do
    request = Sinatra::Request.new('HTTP_X_FORWARDED_PROTO' => 'https')
    assert request.secure?
  end

  it 'is possible to marshal params' do
    request = Sinatra::Request.new(
      'REQUEST_METHOD' => 'PUT',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
      'rack.input' => StringIO.new('foo=bar')
    )
    Sinatra::Base.new!.send(:indifferent_hash).replace(request.params)
    dumped = Marshal.dump(request.params)
    assert_equal 'bar', Marshal.load(dumped)['foo']
  end

  it "exposes the preferred type's parameters" do
    request = Sinatra::Request.new(
      'HTTP_ACCEPT' => 'image/jpeg; compress=0.25'
    )
    assert_equal({ 'compress' => '0.25' }, request.preferred_type.params)
  end

  it "makes accept types behave like strings" do
    request = Sinatra::Request.new('HTTP_ACCEPT' => 'image/jpeg; compress=0.25')
    assert                     request.accept?('image/jpeg')
    assert_equal 'image/jpeg', request.preferred_type.to_s
    assert_equal 'image/jpeg; compress=0.25', request.preferred_type.to_s(true)
    assert_equal 'image/jpeg', request.preferred_type.to_str
    assert_equal 'image',      request.preferred_type.split('/').first

    String.instance_methods.each do |method|
      next unless "".respond_to? method
      assert request.preferred_type.respond_to?(method), "responds to #{method}"
    end
  end

  it "accepts types when wildcards are requested" do
    request = Sinatra::Request.new('HTTP_ACCEPT' => 'image/*')
    assert request.accept?('image/jpeg')
  end

  it "properly decodes MIME type parameters" do
    request = Sinatra::Request.new(
      'HTTP_ACCEPT' => 'image/jpeg;unquoted=0.25;quoted="0.25";chartest="\";,\x"'
    )
    expected = { 'unquoted' => '0.25', 'quoted' => '0.25', 'chartest' => '";,x' }
    assert_equal(expected, request.preferred_type.params)
  end

  it 'accepts */* when HTTP_ACCEPT is not present in the request' do
    request = Sinatra::Request.new Hash.new
    assert_equal 1, request.accept.size
    assert request.accept?('text/html')
    assert_equal '*/*', request.preferred_type.to_s
    assert_equal '*/*', request.preferred_type.to_s(true)
  end

  it 'accepts */* when HTTP_ACCEPT is blank in the request' do
    request = Sinatra::Request.new 'HTTP_ACCEPT' => ''
    assert_equal 1, request.accept.size
    assert request.accept?('text/html')
    assert_equal '*/*', request.preferred_type.to_s
    assert_equal '*/*', request.preferred_type.to_s(true)
  end

  it 'will not accept types not specified in HTTP_ACCEPT when HTTP_ACCEPT is provided' do
    request = Sinatra::Request.new 'HTTP_ACCEPT' => 'application/json'
    assert !request.accept?('text/html')
  end
end
