# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{rack}
  s.version = "1.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Christian Neukirchen"]
  s.date = %q{2009-10-18}
  s.default_executable = %q{rackup}
  s.description = %q{Rack provides minimal, modular and adaptable interface for developing web applications in Ruby.  By wrapping HTTP requests and responses in the simplest way possible, it unifies and distills the API for web servers, web frameworks, and software in between (the so-called middleware) into a single method call.  Also see http://rack.rubyforge.org.}
  s.email = %q{chneukirchen@gmail.com}
  s.executables = ["rackup"]
  s.extra_rdoc_files = ["README", "SPEC", "RDOX", "KNOWN-ISSUES"]
  s.files = ["COPYING", "KNOWN-ISSUES", "README", "Rakefile", "bin/rackup", "contrib/rack_logo.svg", "example/lobster.ru", "example/protectedlobster.rb", "example/protectedlobster.ru", "lib/rack.rb", "lib/rack/adapter/camping.rb", "lib/rack/auth/abstract/handler.rb", "lib/rack/auth/abstract/request.rb", "lib/rack/auth/basic.rb", "lib/rack/auth/digest/md5.rb", "lib/rack/auth/digest/nonce.rb", "lib/rack/auth/digest/params.rb", "lib/rack/auth/digest/request.rb", "lib/rack/auth/openid.rb", "lib/rack/builder.rb", "lib/rack/cascade.rb", "lib/rack/chunked.rb", "lib/rack/commonlogger.rb", "lib/rack/conditionalget.rb", "lib/rack/content_length.rb", "lib/rack/content_type.rb", "lib/rack/deflater.rb", "lib/rack/directory.rb", "lib/rack/file.rb", "lib/rack/handler.rb", "lib/rack/handler/cgi.rb", "lib/rack/handler/evented_mongrel.rb", "lib/rack/handler/fastcgi.rb", "lib/rack/handler/lsws.rb", "lib/rack/handler/mongrel.rb", "lib/rack/handler/scgi.rb", "lib/rack/handler/swiftiplied_mongrel.rb", "lib/rack/handler/thin.rb", "lib/rack/handler/webrick.rb", "lib/rack/head.rb", "lib/rack/lint.rb", "lib/rack/lobster.rb", "lib/rack/lock.rb", "lib/rack/methodoverride.rb", "lib/rack/mime.rb", "lib/rack/mock.rb", "lib/rack/recursive.rb", "lib/rack/reloader.rb", "lib/rack/request.rb", "lib/rack/response.rb", "lib/rack/rewindable_input.rb", "lib/rack/session/abstract/id.rb", "lib/rack/session/cookie.rb", "lib/rack/session/memcache.rb", "lib/rack/session/pool.rb", "lib/rack/showexceptions.rb", "lib/rack/showstatus.rb", "lib/rack/static.rb", "lib/rack/urlmap.rb", "lib/rack/utils.rb", "test/cgi/lighttpd.conf", "test/cgi/test", "test/cgi/test.fcgi", "test/cgi/test.ru", "test/multipart/binary", "test/multipart/empty", "test/multipart/ie", "test/multipart/nested", "test/multipart/none", "test/multipart/semicolon", "test/multipart/text", "test/spec_rack_auth_basic.rb", "test/spec_rack_auth_digest.rb", "test/spec_rack_auth_openid.rb", "test/spec_rack_builder.rb", "test/spec_rack_camping.rb", "test/spec_rack_cascade.rb", "test/spec_rack_cgi.rb", "test/spec_rack_chunked.rb", "test/spec_rack_commonlogger.rb", "test/spec_rack_conditionalget.rb", "test/spec_rack_content_length.rb", "test/spec_rack_content_type.rb", "test/spec_rack_deflater.rb", "test/spec_rack_directory.rb", "test/spec_rack_fastcgi.rb", "test/spec_rack_file.rb", "test/spec_rack_handler.rb", "test/spec_rack_head.rb", "test/spec_rack_lint.rb", "test/spec_rack_lobster.rb", "test/spec_rack_lock.rb", "test/spec_rack_methodoverride.rb", "test/spec_rack_mock.rb", "test/spec_rack_mongrel.rb", "test/spec_rack_recursive.rb", "test/spec_rack_request.rb", "test/spec_rack_response.rb", "test/spec_rack_rewindable_input.rb", "test/spec_rack_session_cookie.rb", "test/spec_rack_session_memcache.rb", "test/spec_rack_session_pool.rb", "test/spec_rack_showexceptions.rb", "test/spec_rack_showstatus.rb", "test/spec_rack_static.rb", "test/spec_rack_thin.rb", "test/spec_rack_urlmap.rb", "test/spec_rack_utils.rb", "test/spec_rack_webrick.rb", "test/testrequest.rb", "test/unregistered_handler/rack/handler/unregistered.rb", "test/unregistered_handler/rack/handler/unregistered_long_one.rb", "SPEC", "RDOX", "rack.gemspec"]
  s.has_rdoc = true
  s.homepage = %q{http://rack.rubyforge.org}
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{rack}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{a modular Ruby webserver interface}
  s.test_files = ["test/spec_rack_auth_basic.rb", "test/spec_rack_auth_digest.rb", "test/spec_rack_auth_openid.rb", "test/spec_rack_builder.rb", "test/spec_rack_camping.rb", "test/spec_rack_cascade.rb", "test/spec_rack_cgi.rb", "test/spec_rack_chunked.rb", "test/spec_rack_commonlogger.rb", "test/spec_rack_conditionalget.rb", "test/spec_rack_content_length.rb", "test/spec_rack_content_type.rb", "test/spec_rack_deflater.rb", "test/spec_rack_directory.rb", "test/spec_rack_fastcgi.rb", "test/spec_rack_file.rb", "test/spec_rack_handler.rb", "test/spec_rack_head.rb", "test/spec_rack_lint.rb", "test/spec_rack_lobster.rb", "test/spec_rack_lock.rb", "test/spec_rack_methodoverride.rb", "test/spec_rack_mock.rb", "test/spec_rack_mongrel.rb", "test/spec_rack_recursive.rb", "test/spec_rack_request.rb", "test/spec_rack_response.rb", "test/spec_rack_rewindable_input.rb", "test/spec_rack_session_cookie.rb", "test/spec_rack_session_memcache.rb", "test/spec_rack_session_pool.rb", "test/spec_rack_showexceptions.rb", "test/spec_rack_showstatus.rb", "test/spec_rack_static.rb", "test/spec_rack_thin.rb", "test/spec_rack_urlmap.rb", "test/spec_rack_utils.rb", "test/spec_rack_webrick.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<test-spec>, [">= 0"])
      s.add_development_dependency(%q<camping>, [">= 0"])
      s.add_development_dependency(%q<fcgi>, [">= 0"])
      s.add_development_dependency(%q<memcache-client>, [">= 0"])
      s.add_development_dependency(%q<mongrel>, [">= 0"])
      s.add_development_dependency(%q<ruby-openid>, ["~> 2.0.0"])
      s.add_development_dependency(%q<thin>, [">= 0"])
    else
      s.add_dependency(%q<test-spec>, [">= 0"])
      s.add_dependency(%q<camping>, [">= 0"])
      s.add_dependency(%q<fcgi>, [">= 0"])
      s.add_dependency(%q<memcache-client>, [">= 0"])
      s.add_dependency(%q<mongrel>, [">= 0"])
      s.add_dependency(%q<ruby-openid>, ["~> 2.0.0"])
      s.add_dependency(%q<thin>, [">= 0"])
    end
  else
    s.add_dependency(%q<test-spec>, [">= 0"])
    s.add_dependency(%q<camping>, [">= 0"])
    s.add_dependency(%q<fcgi>, [">= 0"])
    s.add_dependency(%q<memcache-client>, [">= 0"])
    s.add_dependency(%q<mongrel>, [">= 0"])
    s.add_dependency(%q<ruby-openid>, ["~> 2.0.0"])
    s.add_dependency(%q<thin>, [">= 0"])
  end
end
