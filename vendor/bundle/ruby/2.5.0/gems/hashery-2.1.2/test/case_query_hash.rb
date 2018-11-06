require 'helper'

testcase QueryHash do

  class_method :new do
    test 'new QueryHash with default proc' do
      q = QueryHash.new{ |h,k| h[k] = 1 }
      q[:a].assert == 1
    end
  end

  class_method :[] do
    test 'creates new QueryHash' do
      s = QueryHash[]
      QueryHash.assert === s
    end

    test 'pre-assigns values' do
      s = QueryHash[:a=>1, :b=>2]
      s[:a].assert == 1
      s[:b].assert == 2
    end
  end

  method :[] do
    test 'instance level fetch' do
      s = QueryHash[:a=>1, :b=>2]
      s[:a].assert == 1
      s[:b].assert == 2
      #s['a'].assert == 1
      #s['b'].assert == 2
    end
  end

  method :[]= do
    test do
      s = QueryHash.new
      s[:a] = 1
      s[:b] = 2
      s[:a].assert == 1
      s[:b].assert == 2
      #s['a'].assert == 1
      #s['b'].assert == 2
    end
  end

  method :respond_to? do
    test 'responds to all query methods' do
      q = QueryHash.new
      q.assert.respond_to?(:anything?)
    end

    test 'responds to all bang methods' do
      q = QueryHash.new
      q.assert.respond_to?(:anything!)
    end

    test 'responds to all setter methods' do
      q = QueryHash.new
      q.assert.respond_to?(:anything=)
    end

    test 'responds to usual methods' do
      q = QueryHash.new
      q.assert.respond_to?(:each)
    end
  end

  method :to_hash do
    test do
      s = QueryHash[:a=>1, :b=>2]
      s.to_hash.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :to_h do
   test do
      s = QueryHash[:a=>1, :b=>2]
      s.to_h.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :replace do
    test do
      s = QueryHash.new
      s.replace(:a=>1, :b=>2)
      s.to_h.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :delete do
    test do
      s = QueryHash[:a=>1, :b=>2]
      s.delete(:a)
      s.to_h.assert == {'b'=>2}
    end
  end

  method :each do
    test do
      s = QueryHash[:a=>1, :b=>2]
      s.each do |k,v|
        String.assert === k
      end
    end
  end

  method :store do
    test do
      s = QueryHash.new
      s.store(:a, 1)
      s.to_h.assert == {'a'=>1}
    end
  end

  method :update do
    test do
      s1 = QueryHash[:a=>1,:b=>2]
      s2 = QueryHash[:c=>3,:d=>4]
      s1.update(s2)
      s1.to_h.assert == {'a'=>1,'b'=>2,'c'=>3,'d'=>4}
    end
  end

  method :rekey do
    test do
      s = QueryHash[:a=>1,:b=>2,:c=>3]
      x = s.rekey{ |k| k.upcase }
      x.to_h.assert == {'A'=>1,'B'=>2,'C'=>3}
    end
  end

  method :rekey! do
    test do
      s = QueryHash[:a=>1,:b=>2,:c=>3]
      s.rekey!{ |k| k.upcase }
      s.to_h.assert == {'A'=>1,'B'=>2,'C'=>3}
    end
  end

  method :key? do
    test do
      s = QueryHash[:a=>1]
      s.assert.key?(:a)
      s.assert.key?('a')
    end
  end

  method :has_key? do
    test do
      s = QueryHash[:a=>1]
      s.assert.has_key?(:a)
      s.assert.has_key?('a')
    end
  end

  method :<< do
    test do
      s = QueryHash.new
      s << [:a, 1]
      s << [:b, 2]
      s.to_h.assert == {'a'=>1, 'b'=>2}
    end
  end

  method :merge! do
    test do
      s1 = QueryHash[:a=>1,:b=>2]
      s2 = QueryHash[:c=>3,:d=>4]
      s1.merge!(s2)
      s1.to_h.assert == {'a'=>1,'b'=>2,'c'=>3,'d'=>4}
    end
  end

  method :values_at do
    test do
      s = QueryHash[:a=>1,:b=>2,:c=>3]
      s.values_at(:a, :b).assert == [1,2]
      s.values_at('a','b').assert == [1,2]
    end
  end

  method :fetch do
    test do
      s = QueryHash[:a=>1,:b=>2,:c=>3]
      s.fetch(:a).assert == 1
      s.fetch('a').assert == 1
    end
  end

  method :cast_key do
    test do
      s = QueryHash.new
      s.pry.cast_key(:a).assert == 'a'
    end
  end

  method :method_missing do
    test 'dynamic query methods can look-up values' do
      q = QueryHash[:a=>1,:b=>2,:c=>3]
      q.a?.assert == 1
      q.b?.assert == 2
      q.c?.assert == 3
    end

    test 'dynamic bang methods can looks up values too' do
      q = QueryHash[:a=>1,:b=>2,:c=>3]
      q.a!.assert == 1
      q.b!.assert == 2
      q.c!.assert == 3
    end

    test 'dynamic bang methods will auto-instantiate' do
      q = QueryHash.new
      q.default_proc{ |h,k| h[k] = 'default' }
      q.foo!.assert == 'default'
    end

    test 'dynamic query methods will NOT auto-instantiate' do
      q = QueryHash.new
      q.default_proc{ |h,k| h[k] = 'default' }
      q.foo?.assert == nil
    end
  end

end
