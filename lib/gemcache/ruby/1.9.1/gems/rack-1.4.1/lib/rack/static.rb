module Rack

  # The Rack::Static middleware intercepts requests for static files
  # (javascript files, images, stylesheets, etc) based on the url prefixes or
  # route mappings passed in the options, and serves them using a Rack::File
  # object. This allows a Rack stack to serve both static and dynamic content.
  #
  # Examples:
  #
  # Serve all requests beginning with /media from the "media" folder located
  # in the current directory (ie media/*):
  #
  #     use Rack::Static, :urls => ["/media"]
  #
  # Serve all requests beginning with /css or /images from the folder "public"
  # in the current directory (ie public/css/* and public/images/*):
  #
  #     use Rack::Static, :urls => ["/css", "/images"], :root => "public"
  #
  # Serve all requests to / with "index.html" from the folder "public" in the
  # current directory (ie public/index.html):
  #
  #     use Rack::Static, :urls => {"/" => 'index.html'}, :root => 'public'
  #
  # Serve all requests normally from the folder "public" in the current
  # directory but uses index.html as default route for "/"
  #
  #     use Rack::Static, :urls => [""], :root => 'public', :index =>
  #     'public/index.html'
  #
  # Set a fixed Cache-Control header for all served files:
  #
  #     use Rack::Static, :root => 'public', :cache_control => 'public'
  #

  class Static

    def initialize(app, options={})
      @app = app
      @urls = options[:urls] || ["/favicon.ico"]
      @index = options[:index]
      root = options[:root] || Dir.pwd
      cache_control = options[:cache_control]
      @file_server = Rack::File.new(root, cache_control)
    end

    def overwrite_file_path(path)
      @urls.kind_of?(Hash) && @urls.key?(path) || @index && path == '/'
    end

    def route_file(path)
      @urls.kind_of?(Array) && @urls.any? { |url| path.index(url) == 0 }
    end

    def can_serve(path)
      route_file(path) || overwrite_file_path(path)
    end

    def call(env)
      path = env["PATH_INFO"]

      if can_serve(path)
        env["PATH_INFO"] = (path == '/' ? @index : @urls[path]) if overwrite_file_path(path)
        @file_server.call(env)
      else
        @app.call(env)
      end
    end

  end
end
