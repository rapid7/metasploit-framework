# Rackup config that serves the contents of Rack::Cache's
# doc directory. The documentation is rebuilt on each request.

# Rewrites URLs like conventional web server configs.
class Rewriter < Struct.new(:app)
  def call(env)
    if env['PATH_INFO'] =~ /\/$/
      env['PATH_INFO'] += 'index.html'
    elsif env['PATH_INFO'] !~ /\.\w+$/
      env['PATH_INFO'] += '.html'
    end
    app.call(env)
  end
end

# Rebuilds documentation on each request.
class DocBuilder < Struct.new(:app)
  def call(env)
    if env['PATH_INFO'] !~ /\.(css|js|gif|jpg|png|ico)$/
      env['rack.errors'] << "*** rebuilding documentation (rake -s doc)\n"
      system "rake -s doc"
    end
    app.call(env)
  end
end

use Rack::CommonLogger
use DocBuilder
use Rewriter
use Rack::Static, :root => File.dirname(__FILE__), :urls => ["/"]

run(lambda{|env| [404,{},'<h1>Not Found</h1>']})

# vim: ft=ruby
