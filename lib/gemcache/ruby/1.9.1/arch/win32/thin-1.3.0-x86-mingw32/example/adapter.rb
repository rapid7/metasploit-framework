# Run with: ruby adapter.rb
# Then browse to http://localhost:3000/test
# and http://localhost:3000/files/adapter.rb
require 'thin'

class SimpleAdapter
  def call(env)
    body = ["hello!"]
    [
      200,
      { 'Content-Type' => 'text/plain' },
      body
    ]
  end
end

Thin::Server.start('0.0.0.0', 3000) do
  use Rack::CommonLogger
  map '/test' do
    run SimpleAdapter.new
  end
  map '/files' do
    run Rack::File.new('.')
  end
end

# You could also start the server like this:
#
#   app = Rack::URLMap.new('/test'  => SimpleAdapter.new,
#                          '/files' => Rack::File.new('.'))
#   Thin::Server.start('0.0.0.0', 3000, app)
#
