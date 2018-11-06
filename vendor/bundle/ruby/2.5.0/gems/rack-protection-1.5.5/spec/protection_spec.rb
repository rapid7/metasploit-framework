require File.expand_path('../spec_helper.rb', __FILE__)

describe Rack::Protection do
  it_behaves_like "any rack application"

  it 'passes on options' do
    mock_app do
      use Rack::Protection, :track => ['HTTP_FOO']
      run proc { |e| [200, {'Content-Type' => 'text/plain'}, ['hi']] }
    end

    session = {:foo => :bar}
    get '/', {}, 'rack.session' => session, 'HTTP_ACCEPT_ENCODING' => 'a'
    get '/', {}, 'rack.session' => session, 'HTTP_ACCEPT_ENCODING' => 'b'
    session[:foo].should be == :bar

    get '/', {}, 'rack.session' => session, 'HTTP_FOO' => 'BAR'
    session.should be_empty
  end

  it 'passes errors through if :reaction => :report is used' do
    mock_app do
      use Rack::Protection, :reaction => :report
      run proc { |e| [200, {'Content-Type' => 'text/plain'}, [e["protection.failed"].to_s]] }
    end

    session = {:foo => :bar}
    post('/', {}, 'rack.session' => session, 'HTTP_ORIGIN' => 'http://malicious.com')
    last_response.should be_ok
    body.should == "true"
  end

  describe "#react" do
    it 'prevents attacks and warns about it' do
      io = StringIO.new
      mock_app do
        use Rack::Protection, :logger => Logger.new(io)
        run DummyApp
      end
      post('/', {}, 'rack.session' => {}, 'HTTP_ORIGIN' => 'http://malicious.com')
      io.string.should match /prevented.*Origin/
    end

    it 'reports attacks if reaction is to report' do
      io = StringIO.new
      mock_app do
        use Rack::Protection, :reaction => :report, :logger => Logger.new(io)
        run DummyApp
      end
      post('/', {}, 'rack.session' => {}, 'HTTP_ORIGIN' => 'http://malicious.com')
      io.string.should match /reported.*Origin/
      io.string.should_not match /prevented.*Origin/
    end

    it 'passes errors to reaction method if specified' do
      io = StringIO.new
      Rack::Protection::Base.send(:define_method, :special) { |*args| io << args.inspect }
      mock_app do
        use Rack::Protection, :reaction => :special, :logger => Logger.new(io)
        run DummyApp
      end
      post('/', {}, 'rack.session' => {}, 'HTTP_ORIGIN' => 'http://malicious.com')
      io.string.should match /HTTP_ORIGIN.*malicious.com/
      io.string.should_not match /reported|prevented/
    end
  end

  describe "#html?" do
    context "given an appropriate content-type header" do
      subject { Rack::Protection::Base.new(nil).html? 'content-type' => "text/html" }
      it { should be_true }
    end

    context "given an inappropriate content-type header" do
      subject { Rack::Protection::Base.new(nil).html? 'content-type' => "image/gif" }
      it { should be_false }
    end

    context "given no content-type header" do
      subject { Rack::Protection::Base.new(nil).html?({}) }
      it { should be_false }
    end
  end

  describe "#instrument" do
    let(:env) { { 'rack.protection.attack' => 'base' } }
    let(:instrumenter) { double('Instrumenter') }

    after do
      app.instrument(env)
    end

    context 'with an instrumenter specified' do
      let(:app) { Rack::Protection::Base.new(nil, :instrumenter => instrumenter) }

      it { instrumenter.should_receive(:instrument).with('rack.protection', env) }
    end

    context 'with no instrumenter specified' do
      let(:app) { Rack::Protection::Base.new(nil) }

      it { instrumenter.should_not_receive(:instrument) }
    end
  end
end
