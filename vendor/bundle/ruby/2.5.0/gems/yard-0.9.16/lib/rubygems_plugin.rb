# frozen_string_literal: true
if defined?(Gem::VERSION) && Gem::VERSION >= "2.0."
  require File.expand_path(File.dirname(__FILE__) + '/yard/rubygems/hook')
else
  unless defined?(Gem::DocManager.load_yardoc)
    require File.expand_path(File.dirname(__FILE__) + '/yard/rubygems/specification')
    require File.expand_path(File.dirname(__FILE__) + '/yard/rubygems/doc_manager')
  end
end
