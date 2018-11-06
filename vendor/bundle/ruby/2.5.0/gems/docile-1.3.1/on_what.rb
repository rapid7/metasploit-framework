# NOTE: Very simple tests for what system we are on, extracted for sharing
#   between Rakefile, gemspec, and spec_helper. Not for use in actual library.

def on_travis?
  ENV["CI"] == "true"
end

def on_jruby?
  defined?(RUBY_ENGINE) && "jruby" == RUBY_ENGINE
end

def on_rubinius?
  defined?(RUBY_ENGINE) && "rbx" == RUBY_ENGINE
end

def on_1_8?
  RUBY_VERSION.start_with? "1.8"
end

def on_less_than_1_9_3?
  RUBY_VERSION < "1.9.3"
end

def on_less_than_2_0?
  RUBY_VERSION < "2.0.0"
end
