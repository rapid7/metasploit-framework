### WARNING: there be hax in this file.

require 'rack/session/abstract/id'

describe Rack::Session::Abstract::ID do
  id = Rack::Session::Abstract::ID

  def silence_warning
    o, $VERBOSE = $VERBOSE, nil
    yield
  ensure
    $VERBOSE = o
  end

  def reload_id
    $".delete $".find { |part| part =~ %r{session/abstract/id.rb} }
    silence_warning { require 'rack/session/abstract/id' }
  end

  should "use securerandom when available" do
    begin
      fake = false
      silence_warning do
        ::SecureRandom = fake = true unless defined?(SecureRandom)
      end
      reload_id
      id::DEFAULT_OPTIONS[:secure_random].should.eql(fake || SecureRandom)
    ensure
      Object.send(:remove_const, :SecureRandom) if fake
    end
  end

  should "not use securerandom when unavailable" do
    begin
      sr = Object.send(:remove_const, :SecureRandom) if defined?(SecureRandom)
      reload_id
      id::DEFAULT_OPTIONS[:secure_random].should.eql false
    ensure
      ::SecureRandom = sr if defined?(sr)
    end
  end

end