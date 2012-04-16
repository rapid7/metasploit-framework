require 'rack/body_proxy'
require 'stringio'

describe Rack::BodyProxy do
  should 'call each on the wrapped body' do
    called = false
    proxy  = Rack::BodyProxy.new(['foo']) { }
    proxy.each do |str|
      called = true
      str.should.equal 'foo'
    end
    called.should.equal true
  end

  should 'call close on the wrapped body' do
    body  = StringIO.new
    proxy = Rack::BodyProxy.new(body) { }
    proxy.close
    body.should.be.closed
  end

  should 'only call close on the wrapped body if it responds to close' do
    body  = []
    proxy = Rack::BodyProxy.new(body) { }
    proc { proxy.close }.should.not.raise
  end

  should 'call the passed block on close' do
    called = false
    proxy  = Rack::BodyProxy.new([]) { called = true }
    called.should.equal false
    proxy.close
    called.should.equal true
  end

  should 'call the passed block on close even if there is an exception' do
    object = Object.new
    def object.close() raise "No!" end
    called = false

    begin
      proxy  = Rack::BodyProxy.new(object) { called = true }
      called.should.equal false
      proxy.close
    rescue RuntimeError => e
    end

    raise "Expected exception to have been raised" unless e
    called.should.equal true
  end

  should 'not close more than one time' do
    count = 0
    proxy = Rack::BodyProxy.new([]) { count += 1; raise "Block invoked more than 1 time!" if count > 1 }
    2.times { proxy.close }
    count.should.equal 1
  end

  should 'be closed when the callback is triggered' do
    closed = false
    proxy = Rack::BodyProxy.new([]) { closed = proxy.closed? }
    proxy.close
    closed.should.equal true
  end
end
