require 'helper'

test_case IniHash do

  class_method :new do
    test do
      h = IniHash.new('foo.ini', false)
    end
  end

  method :[]= do
    test do
      h = IniHash.new('foo.ini', false)
      h['a'] = '1'
      h['a'].assert = '1'
    end
  end

  method :[] do
    test do
      h = IniHash.new('foo.ini', false)
      h['a'] = '1'
      h['a'].assert = '1'
    end
  end

  method :to_h do
    test do
      h = IniHash.new('foo.ini', false)
      h['a'] = '1'
      h.to_h.assert = {'a'=>'1'}
    end
  end

  method :to_s do
    test do
      h = IniHash.new('foo.ini', false)
      h['a'] = '1'
      h.to_s.assert == "a=1\n"
    end

    test do
      h = IniHash.new('foo.ini', false)
      h['a'] = '1'
      h['b'] = {'c'=>3}
      h.to_s.assert == "a=1\n[b]\nc=3\n"
    end
  end

  class_method :load do
    h = IniHash.load('test/fixture/example.ini')
    h['a'].assert == '1'
  end

end

