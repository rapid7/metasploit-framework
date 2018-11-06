begin
  require 'minitest'
rescue LoadError
  require 'fivemat/minitest/unit'
  MiniTest::Unit.runner = Fivemat::MiniTest::Unit.new
end
