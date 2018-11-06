require File.expand_path('../helper', __FILE__)
require File.expand_path('../integration_helper', __FILE__)

# These tests start a real server and talk to it over TCP.
# Every test runs with every detected server.
#
# See test/integration/app.rb for the code of the app we test against.
class IntegrationTest < Minitest::Test
  extend IntegrationHelper
  attr_accessor :server

  it('sets the app_file') { assert_equal server.app_file, server.get("/app_file") }
  it('only extends main') { assert_equal "true", server.get("/mainonly") }

  it 'logs once in development mode' do
    next if server.puma? or RUBY_ENGINE == 'jruby'
    random = "%064x" % Kernel.rand(2**256-1)
    server.get "/ping?x=#{random}"
    count = server.log.scan("GET /ping?x=#{random}").count
    if server.net_http_server?
      assert_equal 0, count
    elsif server.webrick?
      assert(count > 0)
    else
      assert_equal(1, count)
    end
  end

  it 'streams' do
    next if server.webrick? or server.trinidad?
    times, chunks = [Time.now], []
    server.get_stream do |chunk|
      next if chunk.empty?
      chunks << chunk
      times << Time.now
    end
    assert_equal ["a", "b"], chunks
    assert times[1] - times[0] < 1
    assert times[2] - times[1] > 1
  end

  it 'streams async' do
    next unless server.thin?

    Timeout.timeout(3) do
      chunks = []
      server.get_stream '/async' do |chunk|
        next if chunk.empty?
        chunks << chunk
        case chunk
        when "hi!"   then server.get "/send?msg=hello"
        when "hello" then server.get "/send?close=1"
        end
      end

      assert_equal ['hi!', 'hello'], chunks
    end
  end

  it 'streams async from subclass' do
    next unless server.thin?

    Timeout.timeout(3) do
      chunks = []
      server.get_stream '/subclass/async' do |chunk|
        next if chunk.empty?
        chunks << chunk
        case chunk
        when "hi!"   then server.get "/subclass/send?msg=hello"
        when "hello" then server.get "/subclass/send?close=1"
        end
      end

      assert_equal ['hi!', 'hello'], chunks
    end
  end

  it 'starts the correct server' do
    exp = %r{
      ==\sSinatra\s\(v#{Sinatra::VERSION}\)\s
      has\staken\sthe\sstage\son\s\d+\sfor\sdevelopment\s
      with\sbackup\sfrom\s#{server}
    }ix

    # because Net HTTP Server logs to $stderr by default
    assert_match exp, server.log unless server.net_http_server?
  end

  it 'does not generate warnings' do
    assert_raises(OpenURI::HTTPError) { server.get '/' }
    server.get '/app_file'
    assert_equal [], server.warnings
  end

  it 'sets the Content-Length response header when sending files' do
    response = server.get_response '/send_file'
    assert response['Content-Length']
  end

  it "doesn't ignore Content-Length header when streaming" do
    response = server.get_response '/streaming'
    assert_equal '46', response['Content-Length']
  end
end
