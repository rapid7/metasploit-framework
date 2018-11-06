# This is copied & modified from MRI
require './test/test_helper'

class TestLazyEnumerator < Test::Unit::TestCase
  def setup
    require "backports/2.0.0/enumerable/lazy"
    require "backports/1.8.7/enumerable"
    require "backports/1.8.7/io/each"
  end

  class Step
    include Enumerable
    attr_reader :current, :args

    def initialize(enum)
      @enum = enum
      @current = nil
      @args = nil
    end

    def each(*args)
      @args = args
      @enum.each {|i| @current = i; yield i}
    end
  end

  def test_initialize
    assert_equal([1, 2, 3], [1, 2, 3].lazy.to_a)
    assert_equal([1, 2, 3], Enumerator::Lazy.new([1, 2, 3]){|y, v| y << v}.to_a)
    assert_raise(ArgumentError) { Enumerator::Lazy.new([1, 2, 3]) }
  end

  ### Backports: Disabled because of Enumerator#each not passing args in MRI < 2.0
  # def test_each_args
  #   a = Step.new(1..3)
  #   assert_equal(1, a.lazy.each(4).first)
  #   assert_equal([4], a.args)
  # end

  def test_each_line
    name = lineno = nil
    File.open(__FILE__) do |f|
      f.each("").map do |paragraph|
        paragraph[/\A\s*(.*)/, 1]
      end.find do |line|
        if name = line[/^class\s+(\S+)/, 1]
          lineno = f.lineno
          true
        end
      end
    end
    assert_equal(self.class.name, name)
    assert_operator(lineno, :>, 2)

    name = lineno = nil
    File.open(__FILE__) do |f|
      ### Backports: Modified to avoid bug of Enumerator#each not passing args in MRI < 2.0
      f.each("").lazy.map do |paragraph| #
        paragraph[/\A\s*(.*)/, 1]
      end.find do |line|
        if name = line[/^class\s+(\S+)/, 1]
          lineno = f.lineno
          true
        end
      end
    end
    assert_equal(self.class.name, name)
    assert_equal(2, lineno)
  end

  def test_select
    a = Step.new(1..6)
    assert_equal(4, a.select {|x| x > 3}.first)
    assert_equal(6, a.current)
    assert_equal(4, a.lazy.select {|x| x > 3}.first)
    assert_equal(4, a.current)

    a = Step.new(['word', nil, 1])
    assert_raise(TypeError) {a.select {|x| "x"+x}.first}
    assert_equal(nil, a.current)
    assert_equal("word", a.lazy.select {|x| "x"+x}.first)
    assert_equal("word", a.current)
  end

  def test_select_multiple_values
    e = Enumerator.new { |yielder|
      for i in 1..5
        yielder.yield(i, i.to_s)
      end
    }
    ### Backport: non lazy version differs on JRuby and MRI
    assert_equal([[2, "2"], [4, "4"]],
                 e.lazy.select {|x| x[0] % 2 == 0}.force)
  end

  def test_map
    a = Step.new(1..3)
    assert_equal(2, a.map {|x| x * 2}.first)
    assert_equal(3, a.current)
    assert_equal(2, a.lazy.map {|x| x * 2}.first)
    assert_equal(1, a.current)
  end

  def test_flat_map
    a = Step.new(1..3)
    assert_equal(2, a.flat_map {|x| [x * 2]}.first)
    assert_equal(3, a.current)
    assert_equal(2, a.lazy.flat_map {|x| [x * 2]}.first)
    assert_equal(1, a.current)
  end if [].respond_to?(:flat_map)

  def test_flat_map_nested
    a = Step.new(1..3)
    assert_equal([1, "a"],
                 a.flat_map {|x| ("a".."c").map {|y| [x, y]}}.first)
    assert_equal(3, a.current)
    assert_equal([1, "a"],
                 a.lazy.flat_map {|x| ("a".."c").lazy.map {|y| [x, y]}}.first)
    assert_equal(1, a.current)
  end if [].respond_to?(:flat_map)

  def test_flat_map_to_ary
    to_ary = Class.new {
      def initialize(value)
        @value = value
      end

      def to_ary
        [:to_ary, @value]
      end
    }
    assert_equal([:to_ary, 1, :to_ary, 2, :to_ary, 3],
                 [1, 2, 3].flat_map {|x| to_ary.new(x)})
    assert_equal([:to_ary, 1, :to_ary, 2, :to_ary, 3],
                 [1, 2, 3].lazy.flat_map {|x| to_ary.new(x)}.force)
  end if [].respond_to?(:flat_map)

  def test_flat_map_non_array
    assert_equal(["1", "2", "3"], [1, 2, 3].flat_map {|x| x.to_s})
    assert_equal(["1", "2", "3"], [1, 2, 3].lazy.flat_map {|x| x.to_s}.force)
  end if [].respond_to?(:flat_map)

  def test_flat_map_hash
    assert_equal([{?a=>97}, {?b=>98}, {?c=>99}], [?a, ?b, ?c].flat_map {|x| {x=>x.ord}})
    assert_equal([{?a=>97}, {?b=>98}, {?c=>99}], [?a, ?b, ?c].lazy.flat_map {|x| {x=>x.ord}}.force)
  end if [].respond_to?(:flat_map)

  def test_reject
    a = Step.new(1..6)
    assert_equal(4, a.reject {|x| x < 4}.first)
    assert_equal(6, a.current)
    assert_equal(4, a.lazy.reject {|x| x < 4}.first)
    assert_equal(4, a.current)

    a = Step.new(['word', nil, 1])
    assert_equal(nil, a.reject {|x| x}.first)
    assert_equal(1, a.current)
    assert_equal(nil, a.lazy.reject {|x| x}.first)
    assert_equal(nil, a.current)
  end

  def test_reject_multiple_values
    e = Enumerator.new { |yielder|
      for i in 1..5
        yielder.yield(i, i.to_s)
      end
    }
    ### Backport: non lazy version differs on JRuby and MRI
    assert_equal([[2, "2"], [4, "4"]],
                 e.lazy.reject {|x| x[0] % 2 != 0}.force)
  end

  def test_grep
    a = Step.new('a'..'f')
    assert_equal('c', a.grep(/c/).first)
    assert_equal('f', a.current)
    assert_equal('c', a.lazy.grep(/c/).first)
    assert_equal('c', a.current)
    assert_equal(%w[a e], a.grep(proc {|x| /[aeiou]/ =~ x}))
    assert_equal(%w[a e], a.lazy.grep(proc {|x| /[aeiou]/ =~ x}).to_a)
  end

  def test_grep_with_block
    a = Step.new('a'..'f')
    assert_equal('C', a.grep(/c/) {|i| i.upcase}.first)
    assert_equal('C', a.lazy.grep(/c/) {|i| i.upcase}.first)
  end

  def test_grep_multiple_values
    e = Enumerator.new { |yielder|
      3.times { |i|
        yielder.yield(i, i.to_s)
      }
    }
    ### Backport: non lazy version differs on JRuby and MRI
    assert_equal([[2, "2"]], e.lazy.grep(proc {|x| x == [2, "2"]}).force)
    assert_equal(["22"],
                 e.lazy.grep(proc {|x| x == [2, "2"]}, &:join).force)
  end

  def test_zip
    a = Step.new(1..3)
    assert_equal([1, "a"], a.zip("a".."c").first)
    assert_equal(3, a.current)
    assert_equal([1, "a"], a.lazy.zip("a".."c").first)
    assert_equal(1, a.current)
  end

  def test_zip_short_arg
    a = Step.new(1..5)
    assert_equal([5, nil], a.zip("a".."c").last)
    enum = [42].to_enum.next
    assert_equal([5, nil], a.lazy.zip("a".."d").force.last)  ### Backport: modified to avoid fact that 1.8.x's Enumerator auto-rewind
  end

  def test_zip_without_arg
    a = Step.new(1..3)
    assert_equal([1], a.zip.first)
    assert_equal(3, a.current)
    avoid_bug_on_jruby = Enumerator.new{|y| y << [1]}.first  ### Backport: see https://jira.codehaus.org/browse/JRUBY-7108
    assert_equal(avoid_bug_on_jruby, a.lazy.zip.first)
    assert_equal(1, a.current)
  end

  def test_zip_bad_arg
    a = Step.new(1..3)
    assert_raise(TypeError){ a.lazy.zip(42) }
  end

  def test_zip_with_block
    # zip should be eager when a block is given
    a = Step.new(1..3)
    ary = []
    assert_equal(nil, a.lazy.zip("a".."c") {|x, y| ary << [x, y]})
    assert_equal(a.zip("a".."c"), ary)
    assert_equal(3, a.current)
  end

  def test_take
    a = Step.new(1..10)
    assert_equal(1, a.take(5).first)
    assert_equal(5, a.current)
    assert_equal(1, a.lazy.take(5).first)
    assert_equal(1, a.current)
    assert_equal((1..5).to_a, a.lazy.take(5).force)
    assert_equal(5, a.current)
    a = Step.new(1..10)
    assert_equal([], a.lazy.take(0).force)
    assert_equal(nil, a.current)
  end

  def test_take_recycle
    bug6428 = '[ruby-dev:45634]'
    a = Step.new(1..10)
    take5 = a.lazy.take(5)
    assert_equal((1..5).to_a, take5.force, bug6428)
    assert_equal((1..5).to_a, take5.force, bug6428)
  end

  def test_take_nested
    bug7696 = '[ruby-core:51470]'
    a = Step.new(1..10)
    take5 = a.lazy.take(5)
    assert_equal([*(1..5)]*5, take5.flat_map{take5}.force, bug7696)
  end

  def test_drop_while_nested
    bug7696 = '[ruby-core:51470]'
    a = Step.new(1..10)
    drop5 = a.lazy.drop_while{|x| x < 6}
    assert_equal([*(6..10)]*5, drop5.flat_map{drop5}.force, bug7696)
  end

  def test_drop_nested
    bug7696 = '[ruby-core:51470]'
    a = Step.new(1..10)
    drop5 = a.lazy.drop(5)
    assert_equal([*(6..10)]*5, drop5.flat_map{drop5}.force, bug7696)
  end

  def test_zip_nested
    bug7696 = '[ruby-core:51470]'
    enum = ('a'..'z').each
    enum.next
    zip = (1..3).lazy.zip(enum, enum)
    assert_equal([[1, 'a', 'a'], [2, 'b', 'b'], [3, 'c', 'c']]*3, zip.flat_map{zip}.force, bug7696)
  end

  def test_zip_lazy_on_args
    zip = Step.new(1..2).lazy.zip(42..Float::INFINITY)
    assert_equal [[1, 42], [2, 43]], zip.force
  end

  def test_zip_efficient_on_array_args
    ary = [42, :foo]
    [:to_enum, :enum_for, :lazy, :each].each do |forbid|
      ary.define_singleton_method(forbid){ fail "#{forbid} was called"}
    end
    zip = Step.new(1..2).lazy.zip(ary)
    assert_equal [[1, 42], [2, :foo]], zip.force
  end

  def test_take_rewound
    bug7696 = '[ruby-core:51470]'
    e=(1..42).lazy.take(2)
    assert_equal 1, e.next
    assert_equal 2, e.next
    e.rewind
    assert_equal 1, e.next
    assert_equal 2, e.next
  end

  def test_take_while
    a = Step.new(1..10)
    assert_equal(1, a.take_while {|i| i < 5}.first)
    assert_equal(5, a.current)
    assert_equal(1, a.lazy.take_while {|i| i < 5}.first)
    assert_equal(1, a.current)
    assert_equal((1..4).to_a, a.lazy.take_while {|i| i < 5}.to_a)
  end

  def test_drop
    a = Step.new(1..10)
    assert_equal(6, a.drop(5).first)
    assert_equal(10, a.current)
    assert_equal(6, a.lazy.drop(5).first)
    assert_equal(6, a.current)
    assert_equal((6..10).to_a, a.lazy.drop(5).to_a)
  end

  def test_drop_while
    a = Step.new(1..10)
    assert_equal(5, a.drop_while {|i| i < 5}.first)
    assert_equal(10, a.current)
    assert_equal(5, a.lazy.drop_while {|i| i < 5}.first)
    assert_equal(5, a.current)
    assert_equal((5..10).to_a, a.lazy.drop_while {|i| i < 5}.to_a)
  end

  def test_drop_and_take
    assert_equal([4, 5], (1..(1.0/0)).lazy.drop(3).take(2).to_a) # Backports: don't rely on INFINITY
  end

  def test_cycle
    a = Step.new(1..3)
    assert_equal("1", a.cycle(2).map{|x| x.to_s}.first)
    assert_equal(3, a.current)
    assert_equal("1", a.lazy.cycle(2).map{|x| x.to_s}.first)
    assert_equal(1, a.current)
  end

  def test_cycle_with_block
    # cycle should be eager when a block is given
    a = Step.new(1..3)
    ary = []
    assert_equal(nil, a.lazy.cycle(2) {|i| ary << i})
    assert_equal(a.cycle(2).to_a, ary)
    assert_equal(3, a.current)
  end

  def test_cycle_chain
    a = 1..3
    assert_equal([1,2,3,1,2,3,1,2,3,1], a.lazy.cycle.take(10).force)
    assert_equal([2,2,2,2,2,2,2,2,2,2], a.lazy.cycle.select {|x| x == 2}.take(10).force)
    assert_equal([2,2,2,2,2,2,2,2,2,2], a.lazy.select {|x| x == 2}.cycle.take(10).force)
  end

  def test_force
    assert_equal([1, 2, 3], (1..Float::INFINITY).lazy.take(3).force)
  end

  def test_inspect
    return unless Enumerator.to_s == "Enumerator"
    assert_equal("#<Enumerator::Lazy: 1..10>", (1..10).lazy.inspect)
    assert_equal('#<Enumerator::Lazy: #<Enumerator: "foo":each_char>>',
                 "foo".each_char.lazy.inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:map>",
                 (1..10).lazy.map {}.inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:take(0)>",
                 (1..10).lazy.take(0).inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:take(3)>",
                 (1..10).lazy.take(3).inspect)
    assert_equal('#<Enumerator::Lazy: #<Enumerator::Lazy: "a".."c">:grep(/b/)>',
                 ("a".."c").lazy.grep(/b/).inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:cycle(3)>",
                 (1..10).lazy.cycle(3).inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:cycle>",
                 (1..10).lazy.cycle.inspect)
    assert_equal("#<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:cycle(3)>",
                 (1..10).lazy.cycle(3).inspect)
    l = (1..10).lazy.map {}.flat_map {}.select {}.reject {}.grep(1).zip(?a..?c).take(10).take_while {}.drop(3).drop_while {}.cycle(3)
    ### Backport: Modified because I don't think the actual name we were called under in case of aliases is important enough to care
    assert_equal(<<EOS.chomp, l.inspect)
#<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: #<Enumerator::Lazy: 1..10>:map>:flat_map>:select>:reject>:grep(1)>:zip(\"a\"..\"c\")>:take(10)>:take_while>:drop(3)>:drop_while>:cycle(3)>
EOS
  end if [].respond_to?(:flat_map)

  def test_lazy_to_enum
    lazy = [1, 2, 3].lazy
    def lazy.foo(*args)
      yield args
      yield args
    end
    enum = lazy.to_enum(:foo, :hello, :world)
    assert_equal Enumerator::Lazy, enum.class
    # assert_equal nil, enum.size  ### Backport: see below
    assert_equal [[:hello, :world], [:hello, :world]], enum.to_a

    assert_equal [1, 2, 3], lazy.to_enum.to_a
  end

  ### Backport: way too much work to shim #size
  # def test_size
  #   lazy = [1, 2, 3].lazy
  #   assert_equal 3, lazy.size
  #   assert_equal 42, Enumerator::Lazy.new([],->{42}){}.size
  #   assert_equal 42, Enumerator::Lazy.new([],42){}.size
  #   assert_equal 42, Enumerator::Lazy.new([],42){}.lazy.size
  #   assert_equal 42, lazy.to_enum{ 42 }.size

  #   [:map, :collect].each do |m|
  #     assert_equal 3, lazy.send(m){}.size
  #   end
  #   assert_equal 3, lazy.zip([4]).size
  #   [:flat_map, :collect_concat, :select, :find_all, :reject, :take_while, :drop_while].each do |m|
  #     assert_equal nil, lazy.send(m){}.size
  #   end
  #   assert_equal nil, lazy.grep(//).size

  #   assert_equal 2, lazy.take(2).size
  #   assert_equal 3, lazy.take(4).size
  #   assert_equal 4, loop.lazy.take(4).size
  #   assert_equal nil, lazy.select{}.take(4).size

  #   assert_equal 1, lazy.drop(2).size
  #   assert_equal 0, lazy.drop(4).size
  #   assert_equal Float::INFINITY, loop.lazy.drop(4).size
  #   assert_equal nil, lazy.select{}.drop(4).size

  #   assert_equal 0, lazy.cycle(0).size
  #   assert_equal 6, lazy.cycle(2).size
  #   assert_equal 3 << 80, 4.times.inject(lazy){|enum| enum.cycle(1 << 20)}.size
  #   assert_equal Float::INFINITY, lazy.cycle.size
  #   assert_equal Float::INFINITY, loop.lazy.cycle(4).size
  #   assert_equal Float::INFINITY, loop.lazy.cycle.size
  #   assert_equal nil, lazy.select{}.cycle(4).size
  #   assert_equal nil, lazy.select{}.cycle.size
  # end

  # def test_map_zip
  #   bug7507 = '[ruby-core:50545]'
  #   assert_ruby_status(["-e", "GC.stress = true", "-e", "(1..10).lazy.map{}.zip(){}"], bug7507)
  #   assert_ruby_status(["-e", "GC.stress = true", "-e", "(1..10).lazy.map{}.zip().to_a"], bug7507)
  # end

  def test_require_block
    [:select, :reject, :drop_while, :take_while, :map, :flat_map].each do |method|
      assert_raise(ArgumentError){ [].lazy.send(method) }
    end
  end

  def test_laziness_conservation
    bug7507 = '[ruby-core:51510]'
    {
      :slice_before => //,
      :with_index => [],
      :cycle => [],
      :each_with_object => 42,
      :each_slice => 42,
      :each_entry => [],
      :each_cons => 42,
    }.each do |method, arg|
      assert_equal Enumerator::Lazy, [].lazy.send(method, *arg).class, method if [].respond_to?(method)
    end
    assert_equal Enumerator::Lazy, [].lazy.chunk{}.class, bug7507
  end

  ### Backport: assert_warning not defined, we're ok anyways
  # def test_no_warnings
  #   le = (1..3).lazy
  #   assert_warning("") {le.zip([4,5,6]).force}
  #   assert_warning("") {le.zip(4..6).force}
  #   assert_warning("") {le.take(1).force}
  #   assert_warning("") {le.drop(1).force}
  #   assert_warning("") {le.drop_while{false}.force}
  # end
end
