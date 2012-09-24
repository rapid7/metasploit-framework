# Ensure we use 'syck' instead of 'psych' in 1.9.2
# RubyGems >= 1.5.0 uses 'psych' on 1.9.2, but
# Psych does not yet support YAML 1.1 merge keys.
# Merge keys is often used in mongoid.yml
# See: http://redmine.ruby-lang.org/issues/show/4300
if RUBY_VERSION >= '1.9.2'
  YAML::ENGINE.yamler = 'syck'
end

Mongoid.configure do |config|
  if Mongoid::VERSION =~ /^3/
    config.sessions = {:default => {:hosts => ['localhost:27017'], :database => 'kaminari_test'}}
  else
    config.master = Mongo::Connection.new.db('kaminari_test')
  end
end
