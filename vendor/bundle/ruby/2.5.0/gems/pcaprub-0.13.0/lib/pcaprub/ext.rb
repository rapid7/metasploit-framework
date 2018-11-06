begin
  if RUBY_VERSION =~ /2.0/
    require '2.0/pcaprub_c'
  elsif RUBY_VERSION =~ /2.1/
    require '2.1/pcaprub_c'
  elsif RUBY_VERSION =~ /2.2/
    require '2.2/pcaprub_c'
  elsif RUBY_VERSION =~ /2.3/
    require '2.3/pcaprub_c'
  else
    require 'pcaprub_c'
  end
rescue Exception
  require 'pcaprub_c'
end
