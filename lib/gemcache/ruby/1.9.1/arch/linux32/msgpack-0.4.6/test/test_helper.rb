require 'test/unit'
begin
require File.dirname(__FILE__) + '/../msgpack'
rescue LoadError
require File.dirname(__FILE__) + '/../lib/msgpack'
end

if ENV["GC_STRESS"]
	GC.stress = true
end
