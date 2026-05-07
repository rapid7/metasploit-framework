# frozen_string_literal: true

# Minimal RSpec boot for specs that only need the http-cookie wrapper (no database).
# Usage:
#   bundle exec rspec spec/lib/msf/core/exploit/remote/http/http_cookie_dependency_spec.rb \
#     --options /dev/null --require spec/http_cookie_dependency_standalone

require 'rspec/core'

ROOT = File.expand_path('..', __dir__)
# Match load order in lib/msf/core/exploit/remote/http/http_cookie_jar.rb so ::HTTP is defined.
require 'http/cookie'
require 'http/cookie_jar'
require 'http/cookie_jar/hash_store'
require File.join(ROOT, 'lib/msf/core/exploit/remote/http/http_cookie_dependency.rb')

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.syntax = :expect
  end
  config.mock_with :rspec do |mocks|
    mocks.syntax = :expect
  end
end
