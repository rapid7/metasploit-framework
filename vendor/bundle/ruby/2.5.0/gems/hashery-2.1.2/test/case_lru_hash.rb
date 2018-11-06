require 'helper'

test_case LRUHash do

  class_method :new do
    h = LRUHash.new(10)
    LRUHash.assert === h
  end

  method :max_size= do
    test do
      h = LRUHash.new(10)
      h.max_size = 100
    end
  end

  method :store do
    test do
      h = LRUHash.new(10)
      h.store(:a, 1)
      h[:a].assert == 1     
    end
  end

  method :[] do
    test do
      h = LRUHash.new(10)
      h.store(:a, 1)
      h[:a].assert == 1
    end

    test do
      h = LRUHash.new(10){ |h,k| h[k] = 0 }
      h[:a].assert == 0
    end
  end

  method :empty? do
    test do
      h = LRUHash.new(10)
      h.assert.empty?
    end
  end

  method :key do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.key(1).assert == :a
    end
  end

  method :keys do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.keys.assert == [:a]
    end
  end

  method :values do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.values.assert == [1]
    end
  end

  method :values_at do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.values_at(:a).assert == [1]
    end
  end

  method :has_key? do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.assert.has_key?(:a)
    end
  end

  method :has_value? do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.assert.has_value?(1)
    end
  end

  method :assoc do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.assoc(:a).assert == [:a,1]
    end
  end

  method :rassoc do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.rassoc(1).assert == [:a,1]
    end
  end

  method :each_key do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.each_key do |k|
        [:a,:b].assert.include?(k)
      end
    end
  end

  method :each_value do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.each_value do |v|
        [1,2].assert.include?(v)
      end
    end
  end

  method :clear do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h[:b] = 2
      h.clear
      h.assert.empty?
    end
  end

  method :delete do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.delete(:a)
      h.assert.empty?     
    end
  end

  method :delete_if do
    test do
      h = LRUHash.new(10)
      h[:a] = 1
      h.delete_if{ |k,v| k == :a }
      h.assert.empty?     
    end
  end

end
