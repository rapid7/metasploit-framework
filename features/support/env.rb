require 'aruba/cucumber'
paths = [
  File.expand_path(File.join(File.dirname(__FILE__))),
  File.expand_path(File.join(File.dirname(__FILE__), %w(.. ..))),
  ENV['PATH']
]
ENV['PATH'] = paths.join(File::PATH_SEPARATOR)
#"#{File.expand_path(File.join(File.dirname(__FILE__)))}#{File::PATH_SEPARATOR}#{ENV['PATH']}"
Before do
    @aruba_timeout_seconds = 60
end