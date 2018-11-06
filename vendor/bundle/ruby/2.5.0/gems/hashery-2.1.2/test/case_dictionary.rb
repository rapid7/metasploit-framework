require 'helper'

testcase Dictionary do
  include AE::Legacy::Assertions

  class_method :[] do
    test do
      d = Dictionary['z', 1, 'a', 2, 'c', 3]
      assert_equal( ['z','a','c'], d.keys )
    end
  end

  class_method :new do
    test "with default" do
      d = Dictionary.new{ |hash,key| hash[key] = 0 }
      d[:a] = 0
      d[:b] += 1
      assert_equal [0, 1],  d.values
      assert_equal [:a,:b], d.keys
    end
  end

  method :[] do
    test do
      d = Dictionary['a', 1]
      d['a'].assert == 1
    end
  end

  method :[]= do
    test do
      d = Dictionary.new
      d['z'] = 1
      d['a'] = 2
      d['c'] = 3
      assert_equal( ['z','a','c'], d.keys )
    end
  end

  method :[]= do
    test do
      d = Dictionary[]
      d[:a] = 1
      d[:c] = 3
      assert_equal( [1,3], d.values )
      d[:b,1] = 2
      assert_equal( [1,2,3], d.values )
      assert_equal( [:a,:b,:c], d.keys )
    end
  end

  method :push do
    test do
      d = Dictionary['a', 1, 'c', 2, 'z', 3]
      assert( d.push('end', 15) )
      assert_equal( 15, d['end'] )
      assert( ! d.push('end', 30) )
      assert( d.unshift('begin', 50) )
      assert_equal( 50, d['begin'] )
      assert( ! d.unshift('begin', 60) )
      assert_equal( ["begin", "a", "c", "z", "end"], d.keys )
      assert_equal( ["end", 15], d.pop )
      assert_equal( ["begin", "a", "c", "z"], d.keys )
      assert_equal( ["begin", 50], d.shift )
    end
  end

  method :insert do
    test "front" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      r = Dictionary['d', 4, 'a', 1, 'b', 2, 'c', 3]
      assert_equal( 4, d.insert(0,'d',4) )
      assert_equal( r, d )
    end
    test "back" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      r = Dictionary['a', 1, 'b', 2, 'c', 3, 'd', 4]
      assert_equal( 4, d.insert(-1,'d',4) )
      assert_equal( r, d )
    end
  end

  method :update do
    test "with other orderred hash" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      c = Dictionary['d', 4]
      r = Dictionary['a', 1, 'b', 2, 'c', 3, 'd', 4]
      assert_equal( r, d.update(c) )
      assert_equal( r, d )
    end
    test "with other hash" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      c = { 'd' => 4 }
      r = Dictionary['a', 1, 'b', 2, 'c', 3, 'd', 4]
      assert_equal( r, d.update(c) )
      assert_equal( r, d )
    end
  end

  method :merge do
    test "with other orderred hash" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      c = Dictionary['d', 4]
      r = Dictionary['a', 1, 'b', 2, 'c', 3, 'd', 4]
      assert_equal( r, d.merge(c) )
    end
    test "with other hash" do
      d = Dictionary['a', 1, 'b', 2, 'c', 3]
      c = { 'd' => 4 }
      r = Dictionary['a', 1, 'b', 2, 'c', 3, 'd', 4]
      assert_equal( r, d.merge(c) )
    end
  end

  method :order_by do
    test do
      d = Dictionary['a', 3, 'b', 2, 'c', 1]
      d.order_by{ |k,v| v }
      assert_equal( [1,2,3], d.values )
      assert_equal( ['c','b','a'], d.keys )
    end
  end

  method :reverse! do
    test do
      d = Dictionary['z', 1, 'a', 2, 'c', 3]
      d.reverse!
      assert_equal( ['c','a','z'], d.keys )
    end
  end

  method :collect do
    test "enumerable method" do
      d = Dictionary[]
      d[:a] = "a"
      d[:c] = "b"
      r = d.collect{|k,v| v.capitalize}
      r.assert == ["A","B"]
    end
  end

  method :dup do
    test "with array values" do
      d = Dictionary.new
      d.dup
      d[:a]=['t',5]
      assert_equal(d, d.dup)
    end
  end

  method :first do
    test do
      d = Dictionary[]
      d[:a] = "a"
      d[:b] = "b"
      d[:c] = "c"
      d.first.assert == "a"
      d.first(0).assert == []
      assert_equal ["a"]       , d.first(1)
      assert_equal ["a", "b"]  , d.first(2)
    end
  end

  method :last do
    test do
      d = Dictionary[]
      d[:a] = "a"
      d[:b] = "b"
      d[:c] = "c"
      d.last.assert == "c"
      d.last(0).assert == []
      d.last(1).assert == ["c"]
      d.last(2).assert == ["b", "c"]
    end
  end

  method :select do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      r = d.select{ |k,v| v % 2 == 1 }
      r.assert == [[:a, 1], [:c, 3]]
    end
  end

  method :to_h do
    test do
      d = Dictionary[:a=>1, :b=>2]
      h = d.to_h
      h.assert == {:a=>1, :b=>2}
    end
  end

  method :replace do
    test do
      d1 = Dictionary[:a=>1, :b=>2]
      d2 = Dictionary[:c=>3, :d=>4]
      d1.replace(d2)
      d1.to_h.assert == {:c=>3, :d=>4}
    end
  end

  method :reverse do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      r = d.reverse
      r.first.assert == 3
    end
  end

  method :invert do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      r = d.invert
      Dictionary.assert === r
      r.to_h.assert == {1=>:a, 2=>:b, 3=>:c}
    end
  end

  method :each_key do
    d = Dictionary[:a=>1, :b=>2, :c=>3]
    d.order_by_key
    a = []
    d.each_key{ |k| a << k }
    a.assert == [:a, :b, :c]
  end

  method :each_value do
    d = Dictionary[:a=>1, :b=>2, :c=>3]
    d.order_by_value
    a = []
    d.each_value{ |v| a << v }
    a.assert == [1, 2, 3]
  end

  method :clear do
    d = Dictionary[:a=>1, :b=>2, :c=>3]
    d.clear
    d.to_a.assert == []
  end

  method :fetch do
    d = Dictionary[:a=>1, :b=>2, :c=>3]
    d.fetch(:a).assert == 1
  end

  method :key? do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.assert.key?(:a)
      d.refute.key?(:d)
    end
  end

  method :has_key? do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.assert.has_key?(:a)
      d.refute.has_key?(:d)
    end
  end

  method :length do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.length.assert == 3
    end
  end

  method :to_a do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.to_a.assert == [[:a,1], [:b,2], [:c,3]]
    end
  end

  method :to_hash do
    test do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.to_hash.assert == {:a=>1, :b=>2, :c=>3}
    end
  end

  method :empty? do
    test "is emtpy" do
      d = Dictionary[]
      d.assert.empty?
    end

    test 'is not emtpy' do
      d = Dictionary[:a=>1, :b=>2, :c=>3]
      d.refute.empty?
    end
  end

  method :order_by_key do
    test do
      d = Dictionary[:b=>1, :c=>2, :a=>4]
      d.order_by_key
      d.order.assert == [:a, :b, :c]
    end
  end

  method :order_by_value do
    test do
      d = Dictionary[:b=>1, :c=>2, :a=>4]
      d.order_by_value
      d.order.assert == [:b, :c, :a]
    end
  end

  class_method :alpha do
    test do
      d = Dictionary.alpha
      d.update(:b=>1, :c=>2, :a=>4)
      d.order.assert == [:a, :b, :c]
    end
  end

  class_method :auto do
    test do
      d = Dictionary.auto
      s = d[:foo]
      s.class.assert == Dictionary
    end
  end

end

