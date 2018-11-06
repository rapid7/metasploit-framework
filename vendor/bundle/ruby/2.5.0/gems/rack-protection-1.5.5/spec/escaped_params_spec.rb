require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection::EscapedParams do
  it_behaves_like "any rack application"

  context 'escaping' do
    it 'escapes html entities' do
      mock_app do |env|
        request = Rack::Request.new(env)
        [200, {'Content-Type' => 'text/plain'}, [request.params['foo']]]
      end
      get '/', :foo => "<bar>"
      body.should == '&lt;bar&gt;'
    end

    it 'leaves normal params untouched' do
      mock_app do |env|
        request = Rack::Request.new(env)
        [200, {'Content-Type' => 'text/plain'}, [request.params['foo']]]
      end
      get '/', :foo => "bar"
      body.should == 'bar'
    end

    it 'copes with nested arrays' do
      mock_app do |env|
        request = Rack::Request.new(env)
        [200, {'Content-Type' => 'text/plain'}, [request.params['foo']['bar']]]
      end
      get '/', :foo => {:bar => "<bar>"}
      body.should == '&lt;bar&gt;'
    end

    it 'leaves cache-breaker params untouched' do
      mock_app do |env|
        [200, {'Content-Type' => 'text/plain'}, ['hi']]
      end

      get '/?95df8d9bf5237ad08df3115ee74dcb10'
      body.should == 'hi'
    end
  end
end
