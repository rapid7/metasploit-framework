require 'cucumber/rails'

require 'aruba/cucumber'

paths = [
  File.expand_path(File.join(File.dirname(__FILE__), %w(.. ..))),
  ENV['PATH']
]
ENV['PATH'] = paths.join(File::PATH_SEPARATOR)

Before do
  @aruba_timeout_seconds = 180
end