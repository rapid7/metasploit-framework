if RUBY_VERSION.to_f >= 1.9
  require 'win32/ruby19/daemon'
else
  require 'win32/ruby18/daemon'
end
