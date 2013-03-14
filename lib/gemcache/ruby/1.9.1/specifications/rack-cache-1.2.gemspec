# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "rack-cache"
  s.version = "1.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Ryan Tomayko"]
  s.date = "2012-03-05"
  s.description = "Rack::Cache is suitable as a quick drop-in component to enable HTTP caching for Rack-based applications that produce freshness (Expires, Cache-Control) and/or validation (Last-Modified, ETag) information."
  s.email = "r@tomayko.com"
  s.extra_rdoc_files = ["README", "COPYING", "TODO", "CHANGES"]
  s.files = ["README", "COPYING", "TODO", "CHANGES"]
  s.homepage = "http://tomayko.com/src/rack-cache/"
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Rack::Cache", "--main", "Rack::Cache"]
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.21"
  s.summary = "HTTP Caching for Rack"

  if s.respond_to? :specification_version then
    s.specification_version = 2

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>, [">= 0.4"])
      s.add_development_dependency(%q<bacon>, [">= 0"])
      s.add_development_dependency(%q<memcached>, [">= 0"])
      s.add_development_dependency(%q<dalli>, [">= 0"])
    else
      s.add_dependency(%q<rack>, [">= 0.4"])
      s.add_dependency(%q<bacon>, [">= 0"])
      s.add_dependency(%q<memcached>, [">= 0"])
      s.add_dependency(%q<dalli>, [">= 0"])
    end
  else
    s.add_dependency(%q<rack>, [">= 0.4"])
    s.add_dependency(%q<bacon>, [">= 0"])
    s.add_dependency(%q<memcached>, [">= 0"])
    s.add_dependency(%q<dalli>, [">= 0"])
  end
end
