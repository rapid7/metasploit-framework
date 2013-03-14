if RUBY_VERSION.to_f >= 1.9
  require File.join(File.dirname(__FILE__), 'ruby19/win32/api')
else
  require File.join(File.dirname(__FILE__), 'ruby18/win32/api')
end
