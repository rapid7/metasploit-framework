begin
  require 'simplecov'
  SimpleCov.start
rescue LoadError
  # okay
end

require File.dirname(__FILE__) + '/../lib/ice_cube'

DAY = Time.utc(2010, 3, 1)
WEDNESDAY = Time.utc(2010, 6, 23, 5, 0, 0)
