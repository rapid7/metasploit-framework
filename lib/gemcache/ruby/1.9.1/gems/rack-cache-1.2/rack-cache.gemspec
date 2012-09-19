Gem::Specification.new do |s|
  s.specification_version = 2 if s.respond_to? :specification_version=
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=

  s.name = 'rack-cache'
  s.version = '1.2'
  s.date = '2012-03-05'

  s.summary     = "HTTP Caching for Rack"
  s.description = "Rack::Cache is suitable as a quick drop-in component to enable HTTP caching for Rack-based applications that produce freshness (Expires, Cache-Control) and/or validation (Last-Modified, ETag) information."

  s.authors = ["Ryan Tomayko"]
  s.email = "r@tomayko.com"

  # = MANIFEST =
  s.files = %w[
    CHANGES
    COPYING
    Gemfile
    README
    Rakefile
    TODO
    doc/configuration.markdown
    doc/faq.markdown
    doc/index.markdown
    doc/layout.html.erb
    doc/license.markdown
    doc/rack-cache.css
    doc/server.ru
    doc/storage.markdown
    example/sinatra/app.rb
    example/sinatra/views/index.erb
    lib/rack-cache.rb
    lib/rack/cache.rb
    lib/rack/cache/appengine.rb
    lib/rack/cache/cachecontrol.rb
    lib/rack/cache/context.rb
    lib/rack/cache/entitystore.rb
    lib/rack/cache/key.rb
    lib/rack/cache/metastore.rb
    lib/rack/cache/options.rb
    lib/rack/cache/request.rb
    lib/rack/cache/response.rb
    lib/rack/cache/storage.rb
    rack-cache.gemspec
    test/cache_test.rb
    test/cachecontrol_test.rb
    test/context_test.rb
    test/entitystore_test.rb
    test/key_test.rb
    test/metastore_test.rb
    test/options_test.rb
    test/pony.jpg
    test/request_test.rb
    test/response_test.rb
    test/spec_setup.rb
    test/storage_test.rb
  ]
  # = MANIFEST =

  s.test_files = s.files.select {|path| path =~ /^test\/.*_test.rb/}

  s.extra_rdoc_files = %w[README COPYING TODO CHANGES]
  s.add_dependency 'rack', '>= 0.4'

  s.add_development_dependency 'bacon'
  s.add_development_dependency 'memcached'
  s.add_development_dependency 'dalli'

  s.has_rdoc = true
  s.homepage = "http://tomayko.com/src/rack-cache/"
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Rack::Cache", "--main", "Rack::Cache"]
  s.require_paths = %w[lib]
  s.rubygems_version = '1.1.1'
end
