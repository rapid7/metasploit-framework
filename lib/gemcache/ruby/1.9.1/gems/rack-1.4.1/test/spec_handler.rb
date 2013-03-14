require 'rack/handler'

class Rack::Handler::Lobster; end
class RockLobster; end

describe Rack::Handler do
  it "has registered default handlers" do
    Rack::Handler.get('cgi').should.equal Rack::Handler::CGI
    Rack::Handler.get('webrick').should.equal Rack::Handler::WEBrick

    begin
      Rack::Handler.get('fastcgi').should.equal Rack::Handler::FastCGI
    rescue LoadError
    end

    begin
      Rack::Handler.get('mongrel').should.equal Rack::Handler::Mongrel
    rescue LoadError
    end
  end

  should "raise LoadError if handler doesn't exist" do
    lambda {
      Rack::Handler.get('boom')
    }.should.raise(LoadError)
  end

  should "get unregistered, but already required, handler by name" do
    Rack::Handler.get('Lobster').should.equal Rack::Handler::Lobster
  end

  should "register custom handler" do
    Rack::Handler.register('rock_lobster', 'RockLobster')
    Rack::Handler.get('rock_lobster').should.equal RockLobster
  end

  should "not need registration for properly coded handlers even if not already required" do
    begin
      $LOAD_PATH.push File.expand_path('../unregistered_handler', __FILE__)
      Rack::Handler.get('Unregistered').should.equal Rack::Handler::Unregistered
      lambda {
        Rack::Handler.get('UnRegistered')
      }.should.raise LoadError
      Rack::Handler.get('UnregisteredLongOne').should.equal Rack::Handler::UnregisteredLongOne
    ensure
      $LOAD_PATH.delete File.expand_path('../unregistered_handler', __FILE__)
    end
  end

  should "allow autoloaded handlers to be registered properly while being loaded" do
    path = File.expand_path('../registering_handler', __FILE__)
    begin
      $LOAD_PATH.push path
      Rack::Handler.get('registering_myself').should.equal Rack::Handler::RegisteringMyself
    ensure
      $LOAD_PATH.delete path
    end
  end
end
