require 'rack/builder'
require 'rack/config'
require 'rack/content_length'
require 'rack/lint'
require 'rack/mock'

describe Rack::Config do
  should "accept a block that modifies the environment" do
    app = Rack::Builder.new do
      use Rack::Lint
      use Rack::ContentLength
      use Rack::Config do |env|
        env['greeting'] = 'hello'
      end
      run lambda { |env|
        [200, {'Content-Type' => 'text/plain'}, [env['greeting'] || '']]
      }
    end

    response = Rack::MockRequest.new(app).get('/')
    response.body.should.equal('hello')
  end
end
