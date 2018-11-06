require 'helper'

# must be required independently
require 'hashery/association'

testcase Association do

  class_method :new do
    test do
      Association.new(:A, :B)
    end
  end

  class_method :[] do
    test do
      a = Association[:a, 1]
      a.assert.index == :a
      a.assert.value == 1
    end
  end

  method :index do
    test do
      a = Association.new(:a,1)
      a.index.assert == :a
    end
  end

  method :value do
    test do
      a = Association.new(:a,1)
      a.value.assert == 1
    end
  end

  method :to_ary do
    test do
      k,v = [],[]
      ohash = [ 'A' >> '3', 'B' >> '2', 'C' >> '1' ]
      ohash.each { |e1,e2| k << e1 ; v << e2 }
      k.assert == ['A','B','C']
      v.assert == ['3','2','1']
    end
  end

  method :index do
    test do
      complex = [ 'Drop Menu' >> [ 'Button 1', 'Button 2', 'Button 3' ], 'Help' ]
      complex[0].index.assert == 'Drop Menu'
    end
  end

  method :<=> do
    test 'when differnt in value' do
      a = Association.new(:a,1)
      b = Association.new(:b,2)
      (a <=> b).assert == -1
      (b <=> a).assert == 1
    end

    test 'when equal value' do
      a = Association.new(:a,1)
      b = Association.new(:b,1)
      (a <=> b).assert == 0
    end
  end

  method :invert! do
    test do
      a = Association.new(:a,1)
      a.invert!
      a.index.assert == 1
      a.value.assert == :a
    end
  end

  method :inspect do
    test do
      a = Association.new(:a,1)
      a.inspect.assert == ":a >> 1"
    end
  end

  method :to_s do
    test do
      a = Association.new(:a,1)
      a.to_s.assert == "a >> 1"
    end
  end

end

testcase Object do
  method :associations do
    test do
      s = 'a'
      complex = [ s >> :b, s >> :c ]
      s.associations.assert == [:b, :c]
    end
  end

end

