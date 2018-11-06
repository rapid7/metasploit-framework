require 'helper'

test_case LinkedList do

  class_method :new do
    ll = LinkedList.new
    LinkedList.assert === ll
  end

  method :to_a do
    test 'empty' do
      ll = LinkedList.new
      ll.to_a.assert == []
    end
    test 'not empty' do
      ll = LinkedList.new
      ll.push :a
      ll.to_a.assert == [:a]
    end
  end

  method :empty? do
    test do
      ll = LinkedList.new
      ll.assert.empty?
    end
  end

  method :delete do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.to_a.assert == [:a]
      ll.delete(:a)
      ll.to_a.assert == []
    end

    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.push :c
      ll.to_a.assert == [:a, :b, :c]
      ll.delete(:b)
      ll.to_a.assert == [:a, :c]
    end
  end

  method :each do
    test do
       a = []
      ll = LinkedList.new
      ll.push :a
      ll.each do |e|
        a << e
      end
      a.assert == [:a]
    end
  end

  method :length do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.length.assert == 1
    end
  end

  method :push do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.to_a.assert == [:a]
    end
  end

  method :unshift do
    test do
      ll = LinkedList.new
      ll.unshift :a
      ll.to_a.assert == [:a]
    end
    test do
      ll = LinkedList.new
      ll.push :a
      ll.unshift :b
      ll.to_a.assert == [:b, :a]
    end
  end

  method :pop do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.to_a.assert == [:a, :b]
      ll.pop
      ll.to_a.assert == [:a]
    end
  end

  method :shift do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.to_a.assert == [:a, :b]
      ll.shift
      ll.to_a.assert == [:b]
    end
  end

  method :first do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.to_a.assert == [:a, :b]
      ll.first.assert == :a
    end
  end

  method :last do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.to_a.assert == [:a, :b]
      ll.last.assert == :b
    end
  end

  method :queue do
    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b
      ll.queue.assert == [:a, :b]
    end
  end

  method :[]= do
    test do
      ll = LinkedList.new
      ll[:a] = :b
      ll.to_a.assert == [:b]
      ll[:a].assert == :b
    end
  end

  method :[] do
    test do
      ll = LinkedList.new
      ll.push :a 
      ll[:a].assert == :a
    end

    test do
      ll = LinkedList.new
      ll.push :a
      ll.push :b  
      ll[:a].assert == :a
      ll[:b].assert == :b
    end
  end

end
