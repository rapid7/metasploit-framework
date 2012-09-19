require 'helper'

class OptionTest < TestCase
  def option(*args, &block)
    Slop.new.option(*args, &block)
  end

  def option_with_argument(*args, &block)
    options = args.shift
    slop = Slop.new
    option = slop.opt(*args)
    slop.parse(options)
    slop.find {|opt| opt.key == option.key }
  end

  def option_value(*args, &block)
    option_with_argument(*args, &block).argument_value
  end

  test 'expects an argument if argument is true or optional is false' do
    assert option(:f, :foo, 'foo', true).expects_argument?
    assert option(:f, :argument => true).expects_argument?
    assert option(:f, :optional => false).expects_argument?

    refute option(:f, :foo).expects_argument?
  end

  test 'expects an argument if long option is suffixed with =' do
    assert option(:f, :foo=).expects_argument?
    assert option('f', 'foo=').expects_argument?
    assert option(:f=).expects_argument?
  end

  test 'accepts an optional argument if optional is true' do
    assert option(:f, :optional => true).accepts_optional_argument?
    assert option(:f, false, :optional => true).accepts_optional_argument?

    refute option(:f, true).accepts_optional_argument?
  end

  test 'has a callback when passed a block or callback option' do
    item = nil
    option(:f){ item = "foo" }.call
    assert_equal "foo", item

    assert option(:callback => proc { item = "bar" }).call
    assert_equal "bar", item

    refute option(:f).call
  end

  test 'splits argument_value with :as => array' do
    assert_equal %w/lee john bill/, option_value(
      %w/--people lee,john,bill/, :people, true, :as => Array
    )

    assert_equal %w/lee john bill/, option_value(
      %w/--people lee:john:bill/,
      :people, true, :as => Array, :delimiter => ':'
    )

    assert_equal ['lee', 'john,bill'], option_value(
      %w/--people lee,john,bill/,
      :people, true, :as => Array, :limit => 2
    )

    assert_equal ['lee', 'john:bill'], option_value(
      %w/--people lee:john:bill/,
      :people, true, :as => Array, :limit => 2, :delimiter => ':'
    )
  end

  test 'casting' do
    assert_equal :foo, option_value(%w/--name foo/, :name, true, :as => Symbol)
    assert_equal :foo, option_value(%w/--name foo/, :name, true, :as => :symbol)
    assert_equal :foo, option_value(%w/--name foo/, :name, true, :as => :sym)
    assert_equal 30, option_value(%w/--age 30/, :age, true, :as => Integer)
    assert_equal "1.0", option_value(%w/--id 1/, :id, true, :as => Float).to_s

    assert_equal -1, option_value(%w/-i -1/, :i, true, :as => Integer)
    assert_equal -1, option_value(%w/-i -1.1/, :i, true, :as => Integer)
    assert_equal "-1.1", option_value(%w/-i -1.1/, :i, true, :as => Float).to_s
    assert_equal "foo", option_value(%w/--foo1 foo/, :foo1, true)

    assert_equal 0, option_value(%w//, :v, :verbose, :as => :count)
    assert_equal 1, option_value(%w/--verbose/, :v, :verbose, :as => :count)
    assert_equal 2, option_value(%w/--verbose -v/, :v, :verbose, :as => :count)
    assert_equal 3, option_value(%w/-vvv/, :v, :verbose, :as => :count)

    assert_equal 1, option_value(%w/-i 1/, :i, true, :as => proc { |x| x.to_i })
    assert_equal "oof", option_value(%w/-i foo/, :i, true, :as => proc { |x| x.reverse })
  end

  test 'casting should return nil for optionless arguments' do
    assert_equal nil, option_value(%w/-i/, :i, :as => :int)
    assert_equal nil, option_value(%w/-i/, :i, :as => :str)
    assert_equal nil, option_value(%w/-i/, :i, :as => :float)
    assert_equal nil, option_value(%w/-i/, :i, :as => :array)
    assert_equal nil, option_value(%w/-i/, :i, :as => :range)

    assert_equal nil, option_value(%w/-i/, :i, :optional => true, :as => :range)
  end

  test 'ranges' do
    assert_equal (1..10), option_value(%w/-r 1..10/, :r, true, :as => Range)
    assert_equal (1..10), option_value(%w/-r 1-10/, :r, true, :as => Range)
    assert_equal (1..10), option_value(%w/-r 1,10/, :r, true, :as => Range)
    assert_equal (1...10), option_value(%w/-r 1...10/, :r, true, :as => Range)
    assert_equal (-1..10), option_value(%w/-r -1..10/, :r, true, :as => Range)
    assert_equal (1..-10), option_value(%w/-r 1..-10/, :r, true, :as => Range)

    # default back to the string unless a regex is successful
    # return value.to_i if the value is /\A\d+\z/
    # maybe this should raise if Slop#strict?
    assert_equal "1abc10", option_value(%w/-r 1abc10/, :r, true, :as => Range)
    assert_equal (1..1), option_value(%w/-r 1/, :r, true, :as => Range)
    assert_equal (2..2), option_value(%w/-r 2/, :r, true, :as => Range)
  end

  test 'printing options' do
    slop = Slop.new
    slop.opt :n, :name, 'Your name', true
    slop.opt :age, 'Your age', true
    slop.opt :V, 'Display the version'

    assert_equal "    -n, --name      Your name", slop.options[:name].to_s
    assert_equal "        --age       Your age", slop.options[:age].to_s
    assert_equal "    -V,             Display the version", slop.options[:V].to_s
  end

  test 'falls back to default option' do
    slop = Slop.new
    slop.opt :foo, :optional => true, :default => 'lee'
    slop.parse %w/--foo/
    assert_equal 'lee', slop[:foo]
  end

  test 'key should default to long flag otherwise use short flag' do
    assert_equal 'foo', option(:f, :foo).key
    assert_equal 'b', option(:b).key
  end

  test 'tail to append items to the options list when printing help' do
    slop = Slop.new
    slop.on :f, :foo, :tail => true
    slop.on :b, :bar
    assert slop.to_s.strip =~ /foo$/
  end

  test 'do not print help for options with :help => false' do
    slop = Slop.new
    slop.on :f, :foo, :help => false
    refute slop.help.include?('foo')
  end

  test 'appends a help string with :help => "string"' do
    slop = Slop.new
    slop.on :n, :name, 'Your name', true, :help => '<YOUR NAME HERE>'
    assert_equal '    -n, --name <YOUR NAME HERE>     Your name', slop.options[:name].to_s
  end

  test 'argument matching' do
    slop = Slop.new
    slop.on :f, :foo, true, :match => /^h/

    assert_raises(Slop::InvalidArgumentError, /world/) { slop.parse %w/--foo world/ }
    assert slop.parse %w/--foo hello/
  end

  test 'non-casting of nil options' do
    slop = Slop.new { on :f, :foo, true, :as => String }
    slop.parse []

    assert_equal nil, slop[:foo]
    refute_equal "", slop[:foo]
  end

  test 'counting options' do
    slop = Slop.new { on :v; on :x }
    slop.parse %w/-v -v -v -x/
    assert_equal 1, slop.options[:x].count
    assert_equal 3, slop.options[:v].count
  end

  test 'omit block execution with :unless option' do
    item = nil
    opts = Slop.new do
      on :foo
      on :bar, true, :unless => 'foo' do; item = "foo"; end
    end
    opts.parse %w/--foo --bar 1/

    assert_equal "1", opts[:bar]
    refute item
  end

  test 'raises MissingOptionError when an option is :required' do
    opts = Slop.new do
      on :foo, :required => true
    end

    assert_raises(Slop::MissingOptionError, /foo is required/) { opts.parse %w[ --bar ] }
    assert_raises(Slop::MissingOptionError, /foo is required/) { opts.parse %w[ foo ] }
  end
end
