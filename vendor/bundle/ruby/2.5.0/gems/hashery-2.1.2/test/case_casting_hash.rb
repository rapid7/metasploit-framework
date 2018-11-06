require 'helper'

test_case CastingHash do

  class_method :[] do
    test do
      h = CastingHash[:a=>1, :b=>2]
    end
  end

  class_method :new do
    test do
      h = CastingHash.new
    end

    test 'with default' do
      h = CastingHash.new(0)
      h['a'].assert == 0
    end

    test 'with casting procedure' do
      h = CastingHash.new{ |k,v| [k.to_sym, v] }
      h['a'] = 1
      h.assert == {:a=>1}
    end

    test 'with default and casting procedure' do
      h = CastingHash.new(0){ |k,v| [k.to_sym, v] }
      h['a'].assert == 0
      h['b'] = 2
      h.assert == {:b=>2}
    end
  end

  method :recast! do
    test do
      h = CastingHash[:a=>1, :b=>2]
      h.cast_proc{ |k,v| [k.to_s, v] }
      h.recast!
      h.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :cast_proc= do
    test do
      h = CastingHash[:a=>1, :b=>2]
      h.cast_proc = Proc.new{ |k,v| [k.to_s, v] }
      h.recast!
      h.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :to_hash do
    test do
      h = CastingHash[:a=>1, :b=>2]
      h.to_hash
      ::Hash.assert === h
      h.assert == {:a=>1, :b=>2}
    end
  end

  method :to_h do
    test do
      h = CastingHash[:a=>1, :b=>2]
      h.to_h
      ::Hash.assert === h
      h.assert == {:a=>1, :b=>2}
    end
  end

end
