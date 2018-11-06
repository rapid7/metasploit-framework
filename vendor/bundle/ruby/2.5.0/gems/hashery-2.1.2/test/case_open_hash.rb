require 'helper'

testcase OpenHash do

  class_method :[] do
    test do
      o = OpenHash[:a=>1, :b=>2]
      o.a.assert == 1
      o.b.assert == 2
    end

    test do
      o = OpenHash[:a=>1, :b=>2]
      o.a.assert == 1
      o.b.assert == 2
    end
  end

  method :open? do
    test do
      o = OpenHash[:a=>1, :b=>2]
      o.assert.open?(:foo)
      o.refute.open?(:each)
    end
  end

  method :open! do
    test do
      o = OpenHash[:a=>1, :b=>2]
      o.open!(:each)
      o.assert.open?(:each)
      o.each = 10
      o.each.assert == 10
    end
  end

  method :close! do
    test do
      o = OpenHash[:a=>1, :b=>2]
      o.open!(:each)
      o.assert.open?(:each)
      o.each = 10
      o.each.assert == 10
      o.close!(:each)
      o.each.refute == 10
    end
  end

  method :method_missing do
    test 'bang method' do
      o = OpenHash[]
      o.open!(:each)
      o.each = 10
      o.each.assert == 10

      a = []
      o.each! do |k,v|
        a << [k,v]
      end
      a.assert == [[:each,10]]
    end

    test 'query method' do
      o = OpenHash[]
      o.a = 1
      o.assert.a?
      o.refute.b?
    end
  end

  method :send do
    test do
      o = OpenHash[]
      o.open!(:each)
      o.each = 10
      o.each.assert == 10

      a = []
      o.send(:each) do |k,v|
        a << [k,v]
      end
      a.assert == [[:each,10]]
    end
  end

end

