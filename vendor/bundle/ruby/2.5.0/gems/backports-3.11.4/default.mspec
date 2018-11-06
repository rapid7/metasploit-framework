if (Backports::TARGET_VERSION rescue false) # Conf loaded at different times, not sure why
  class MSpecScript
    # The set of substitutions to transform a spec filename
    # into a tag filename.
    set :tags_patterns, [ [%r(rubyspec/), "tags/#{RUBY_VERSION}/"] ]
  end

  SpecGuard.ruby_version_override = Backports::TARGET_VERSION if Backports::TARGET_VERSION > RUBY_VERSION
end
