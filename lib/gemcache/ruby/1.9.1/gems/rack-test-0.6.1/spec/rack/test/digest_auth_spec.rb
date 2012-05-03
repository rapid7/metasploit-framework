require "spec_helper"

describe Rack::Test::Session do
  context "HTTP Digest authentication" do

    def app
      app = Rack::Auth::Digest::MD5.new(Rack::Test::FakeApp.new) do |username|
        { 'alice' => 'correct-password' }[username]
      end
      app.realm = 'WallysWorld'
      app.opaque = 'this-should-be-secret'
      app
    end

    it 'incorrectly authenticates GETs' do
      digest_authorize 'foo', 'bar'
      get '/'
      last_response.should be_challenge
    end

    it "correctly authenticates GETs" do
      digest_authorize "alice", "correct-password"
      response = get "/"
      response.should be_ok
    end

    it "correctly authenticates POSTs" do
      digest_authorize "alice", "correct-password"
      response = post "/"
      response.should be_ok
    end

    it "returns a re-challenge if authenticating incorrectly" do
      digest_authorize "alice", "incorrect-password"
      response = get "/"
      response.should be_challenge
    end

  end
end
