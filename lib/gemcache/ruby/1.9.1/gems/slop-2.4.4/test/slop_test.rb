require 'helper'

class SlopTest < TestCase
  def clean_options(*args)
    Slop.new.send(:clean_options, args)
  end

  def temp_argv(items)
    old_argv = ARGV.clone
    ARGV.replace items
    yield
  ensure
    ARGV.replace old_argv
  end

  test 'includes Enumerable' do
    assert Slop.included_modules.include?(Enumerable)
  end

  test 'new accepts a hash or array of symbols' do
    slop = Slop.new :strict, :multiple_switches => true
    [ :@multiple_switches, :@strict ].each do |var|
      assert slop.instance_variable_get var
    end
  end

  test 'parse returns a Slop object' do
    slop = Slop.parse([])
    assert_kind_of Slop, slop
  end

  test 'parsing calls to_s on all of the items in the array' do
    opts = Slop.parse([:'--foo']) { on :foo }
    assert opts.foo?
  end

  test '#opt returns an Slop::Option' do
    assert_kind_of Slop::Option, Slop.new.option(:n)
  end

  test 'enumerating options' do
    slop = Slop.new
    slop.opt(:f, :foo, 'foo')
    slop.opt(:b, :bar, 'bar')

    slop.each { |option| assert_kind_of Slop::Option, option }
  end

  test 'defaulting to ARGV' do
    temp_argv(%w/--name lee/) do
      assert_equal('lee', Slop.parse { on :name, true }[:name])
    end
  end

  test 'callback when option array is empty' do
    item1 = nil
    temp_argv([]) do
      Slop.new { on_empty { item1 = 'foo' } }.parse
    end

    assert_equal 'foo', item1

    temp_argv([]) do
      assert_equal [], Slop.new { on_empty {} }.parse
    end
  end

  test 'callback when arguments contain no options' do
    item = nil
    Slop.new { on_optionless { item = 'foo' } }.parse %w/a b c/
    assert_equal 'foo', item
  end

  test 'multiple switches with the :multiple_switches flag' do
    slop = Slop.new :multiple_switches => true, :strict => true
    %w/a b c/.each { |f| slop.on f }
    slop.on :z, true
    slop.parse %w/-abc/

    %w/a b c/.each do |flag|
      assert slop[flag]
      assert slop.send(flag + '?')
    end

    assert_raises(Slop::InvalidOptionError, /d/)   { slop.parse %w/-abcd/ }
    assert_raises(Slop::MissingArgumentError, /z/) { slop.parse %w/-abcz/ }

    slop = Slop.new(:multiple_switches)
    slop.on :a
    slop.on :f, true
    args = %w[-abc -f foo bar]
    slop.parse! args

    assert_equal %w[ bar ], args
    assert_equal 'foo', slop[:f]
    assert slop[:a]
  end

  test 'passing a block' do
    assert Slop.new {}
    slop = nil
    assert Slop.new {|s| slop = s }
    assert_kind_of Slop, slop
  end

  test 'automatically adding the help option' do
    slop = Slop.new
    assert_empty slop.options

    slop = Slop.new :help => true
    refute_empty slop.options
    assert_equal 'Print this help message', slop.options[:help].description
  end

  test ':all_accept_arguments' do
    opts = Slop.new(:all_accept_arguments) do
      on :foo
      on :bar, :optional => true
    end
    opts.parse %w[ --foo hello --bar ]

    assert_equal 'hello', opts[:foo]
    assert_nil opts[:bar]
    assert_raises(Slop::MissingArgumentError) { opts.parse %w[ --foo --bar ] }
  end

  test 'yielding non-options when a block is passed to "parse"' do
    opts = Slop.new do
      on :name, true
    end
    opts.parse(%w/--name lee a/) do |v|
      assert_equal 'a', v
    end
  end

  test 'preserving order when yielding non-options' do
    items = []
    slop = Slop.new { on(:name, true) { |name| items << name } }
    slop.parse(%w/foo --name bar baz/) { |value| items << value }
    assert_equal %w/foo bar baz/, items
  end

  test 'only parsing options' do
    slop = Slop.new { on :n, true }
    assert slop.parse %w/n/
  end

  test 'setting the banner' do
    slop = Slop.new
    slop.banner = "foo bar"

    assert_equal "foo bar", slop.banner
    assert slop.to_s =~ /^foo bar/

    slop.banner = nil
    assert_equal "", slop.to_s

    slop = Slop.new "foo bar"
    assert_equal "foo bar", slop.banner

    slop = Slop.new :banner => "foo bar"
    assert_equal "foo bar", slop.banner
  end

  test 'setting the summary' do
    slop = Slop.new
    slop.banner = "foo bar"
    slop.summary = "does stuff"

    assert_equal "foo bar\n\ndoes stuff", slop.to_s
  end

  test 'setting the description' do
    slop = Slop.new
    slop.banner     = "foo bar"
    slop.summary = "does stuff"
    slop.description  = "This does stuff."

    assert_equal "foo bar\n\ndoes stuff\n\n    This does stuff.", slop.to_s
  end

  test 'setting the description without matching summary' do
    slop = Slop.new
    slop.banner     = "foo bar"
    slop.description  = "This does stuff."

    assert_equal "foo bar\n\n    This does stuff.", slop.to_s
  end

  test 'storing long option lengths' do
    slop = Slop.new
    assert_equal 0, slop.longest_flag
    slop.opt(:name)
    assert_equal 4, slop.longest_flag
    slop.opt(:username)
    assert_equal 8, slop.longest_flag
  end

  test 'parse returning the list of arguments left after parsing' do
    opts = Slop.new do
      on :name, true
    end
    assert_equal %w/a/, opts.parse!(%w/--name lee a/)
    assert_equal %w/--name lee a/, opts.parse(%w/--name lee a/)
    assert_equal ['foo', :bar, 1], opts.parse(['foo', :bar, 1])
  end

  test '#parse does not remove parsed items' do
    items = %w/--foo/
    Slop.new { |opt| opt.on :foo }.parse(items)
    assert_equal %w/--foo/, items
  end

  test '#parse! removes parsed items' do
    items = %w/--foo/
    Slop.new { |opt| opt.on :foo }.parse!(items)
    assert_empty items
  end

  test '#parse! does not remove unparsed items with same value as a parsed item' do
    items = %w/bar --foo bar/
    Slop.new { |opt| opt.on :foo, 'foo', true }.parse!(items)
    assert_equal %w/bar/, items
  end

  test '#parse! removes parsed items prefixed with --no-' do
    items = %w/--no-foo/
    Slop.new { |opt| opt.on :foo }.parse!(items)
    assert_empty items
  end

  test 'the shit out of clean_options' do
    assert_equal(
      ['s', 'short', 'short option', false, {}],
      clean_options('-s', '--short', 'short option')
    )

    assert_equal(
      [nil, 'long', 'long option only', true, {}],
      clean_options('--long', 'long option only', true)
    )

    assert_equal(
      ['S', 'symbol', 'symbolize', false, {}],
      clean_options(:S, :symbol, 'symbolize')
    )

    assert_equal(
      ['a', nil, 'alphabetical only', true, {}],
      clean_options('a', 'alphabetical only', true)
    )

    assert_equal( # for description-less options
      [nil, 'optiononly', nil, false, {}],
      clean_options('--optiononly')
    )

    assert_equal(
      ['f', 'foo', 'some description', false, {:optional => false, :help => 'BAR'}],
      clean_options(:f, 'foo BAR', 'some description')
    )

    assert_equal(
      [nil, 'bar', nil, false, {:optional => true, :help => '[STUFF]'}],
      clean_options('bar [STUFF]')
    )

    assert_equal([nil, 'foo', nil, false, {:as => Array}], clean_options(:foo, Array, false))
    assert_equal([nil, 'foo', nil, false, {:as => Array}], clean_options(Array, :foo, false))

    assert_equal(['c', nil, nil, true, {}], clean_options(:c, true))
    assert_equal(['c', nil, nil, false, {}], clean_options(:c, false))
  end

  test '[] returns an options argument value or a command or nil (in that order)' do
    slop = Slop.new
    slop.opt :n, :name, true
    slop.opt :foo
    slop.command(:foo) { }
    slop.command(:bar) { }
    slop.parse %w/--name lee --foo/

    assert_equal 'lee', slop[:name]
    assert_equal 'lee', slop[:n]

    assert_equal true, slop[:foo]
    assert_kind_of Slop, slop[:bar]

    assert_nil slop[:baz]
  end

  test 'arguments ending ? test for option existance' do
    slop = Slop.new
    slop.opt :v, :verbose
    slop.opt :d, :debug
    slop.parse %w/--verbose/

    assert slop[:verbose]
    assert slop.verbose?

    refute slop[:debug]
    refute slop.debug?
  end

  test 'options are present' do
    opts = Slop.new do
      on :f, 'foo-bar'
      on :b, 'bar-baz'
      on :h, :optional => true
    end
    opts.parse %w/--foo-bar -h/

    assert opts.present?('foo-bar')
    refute opts.present?('bar-baz')
    refute opts.present?('foo-bar', 'bar-baz')
    assert opts.present?(:h)
  end

  test 'raises if an option expects an argument and none is given' do
    slop = Slop.new
    slop.opt :name, true
    slop.opt :age, :optional => true

    assert_raises(Slop::MissingArgumentError, /name/) { slop.parse %w/--name/ }
    assert slop.parse %w/--name 'foo'/
  end

  test 'returning a hash of options' do
    slop = Slop.new
    slop.opt :name, true
    slop.opt :version
    slop.opt :V, :verbose, :default => false
    slop.parse %w/--name lee --version/

    assert_equal({'name' => 'lee', 'version' => true, 'verbose' => false}, slop.to_hash(false))
    assert_equal({:name => 'lee', :version => true, :verbose => false}, slop.to_hash(true))
  end

  test 'iterating options' do
    slop = Slop.new
    slop.opt :a, :abc
    slop.opt :f, :foo

    assert_equal 2, slop.count
    slop.each {|opt| assert_kind_of Slop::Option, opt }
  end

  test 'fetching options and option values' do
    slop = Slop.new
    slop.opt :foo, true
    slop.parse %w/--foo bar/

    assert_kind_of Slop::Option, slop.options[:foo]
    assert_equal "bar", slop[:foo]
    assert_equal "bar", slop['foo']
    assert_kind_of Slop::Option, slop.options[0]
    assert_nil slop.options['0']
  end

  test 'printing help' do
    slop = Slop.new
    slop.banner = 'Usage: foo [options]'
    slop.parse
    assert slop.to_s =~ /^Usage: foo/
  end

  test 'passing argument values to blocks' do
    name = nil
    opts = Slop.new
    opts.on :name, true, :callback => proc {|n| name = n}
    opts.parse %w/--name lee/
    assert_equal 'lee', name
  end

  test 'strict mode' do
    strict = Slop.new :strict => true
    totallynotstrict = Slop.new

    assert_raises(Slop::InvalidOptionError, /--foo/) { strict.parse %w/--foo/ }
    assert totallynotstrict.parse %w/--foo/
  end

  test 'strict mode parses options before raising Slop::InvalidOptionError' do
    strict = Slop.new :strict => true
    strict.opt :n, :name, true

    assert_raises(Slop::InvalidOptionError, /--foo/) { strict.parse %w/--foo --name nelson/ }
    assert_equal 'nelson', strict[:name]
  end

  test 'short option flag with no space between flag and argument, with :multiple_switches => false' do
    slop = Slop.new :multiple_switches => false
    slop.opt :p, :password, true
    slop.opt :s, :shortpass, true
    slop.parse %w/-pfoo -sbar/

    assert_equal 'foo', slop[:password]
    assert_equal 'bar', slop[:shortpass]
  end

  test 'prefixing --no- onto options for a negative result' do
    slop = Slop.new
    slop.opt :d, :debug
    slop.opt :v, :verbose, :default => true
    slop.parse %w/--no-debug --no-verbose --no-nothing/

    refute slop.verbose?
    refute slop.debug?
    refute slop[:verbose]
    refute slop[:debug]
  end

  test 'option=value' do
    slop = Slop.new
    slop.opt :n, :name, true
    slop.parse %w/--name=lee/

    assert_equal 'lee', slop[:name]
    assert slop.name?
  end

  test 'parsing options with options as arguments' do
    slop = Slop.new { on :f, :foo, true }
    assert_raises(Slop::MissingArgumentError) { slop.parse %w/-f --bar/ }
  end

  test 'respond_to?' do
    slop = Slop.new { on :f, :foo }
    assert slop.respond_to?('foo?')
    refute slop.respond_to?('foo')
  end

  test 'reusable slop object (ie not using define_method for present?())' do
    slop = Slop.new { on :f, :foo }

    slop.parse %w()
    assert_equal false, slop.foo?

    slop.parse %w( --foo )
    assert_equal true, slop.foo?
  end

  test 'custom IO object' do
    io = StringIO.new
    slop = Slop.new(:help => true, :io => io)
    slop.on :f, :foo, 'something fooey'
    begin
      slop.parse %w/--help/
    rescue SystemExit
    end
    assert io.string.include? 'something fooey'
  end

  test 'exiting when using :help option' do
    io = StringIO.new
    opts = Slop.new(:help => true, :io => io)
    assert_raises(SystemExit) { opts.parse %w/--help/ }

    opts = Slop.new(:help => true, :io => io, :exit_on_help => false)
    assert opts.parse %w/--help/
  end

  test 'ignoring case' do
    opts = Slop.new(:ignore_case => true)
    opts.on :n, :name, true
    opts.parse %w/--NAME lee/
    assert_equal 'lee', opts[:name]
  end

  test 'autocreating options' do
    opts = Slop.new(:autocreate => true) do |o|
      o.on '--lorem', true
    end
    opts.parse %w/--hello --foo bar -a --lorem ipsum/

    assert opts.hello?
    assert opts.foo?
    assert_equal 'bar', opts[:foo]
    assert opts.a?
    assert_equal 'ipsum', opts[:lorem]
  end

  test 'multiple elements for array option' do
    opts = Slop.new do
      on :a, true, :as => Array
    end
    opts.parse %w/-a foo -a bar baz -a etc/

    assert_equal %w/foo bar etc/, opts[:a]
  end

  test ':arguments => true' do
    opts = Slop.new(:arguments) { on :foo }
    opts.parse %w/--foo bar/

    assert_equal 'bar', opts[:foo]
  end

  test 'long flag strings' do
    opts = Slop.new do
      on 'f', 'foo BAR'
      on 'bar [HELLO]'
    end

    assert opts.options[:foo].expects_argument?
    assert opts.options[:bar].accepts_optional_argument?

    assert_equal '    -f, --foo BAR     ', opts.options[:foo].to_s
    assert_equal '        --bar [HELLO] ', opts.options[:bar].to_s
  end

  test 'not parsing options if after --' do
    args = %w[ foo bar -- --foo bar ]
    opts = Slop.parse!(args) do
      on :foo, true
    end

    assert_equal %w[ foo bar --foo bar ], args
  end

  test 'inline classes' do
    opts = Slop.new do
      on :foo, Array, true
      on Symbol, :bar, true
    end
    opts.parse %w/--foo one,two --bar hello/

    assert_equal %w[one two], opts[:foo]
    assert_equal :hello, opts[:bar]
  end

  test 'wrap and indent' do
    slop = Slop.new

    assert_equal(
      "Lorem ipsum dolor sit amet, consectetur\n" +
      "adipisicing elit, sed do eiusmod tempor\n" +
      "incididunt ut labore et dolore magna\n" +
      "aliqua.",
      slop.send(:wrap_and_indent, "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", 40, 0))

    assert_equal(
      "    Lorem ipsum dolor sit amet,\n" +
      "    consectetur adipisicing elit, sed\n" +
      "    do eiusmod tempor incididunt ut\n" +
      "    labore et dolore magna aliqua.",
      slop.send(:wrap_and_indent, "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", 36, 4))
  end

  test 'to_struct' do
    assert_nil Slop.new.to_struct

    slop = Slop.new { on :a, true }
    slop.parse %w[ -a foo -b ]
    struct = slop.to_struct

    assert_equal 'foo', struct.a
    assert_kind_of Struct, struct
    assert_raises(NoMethodError) { struct.b }

    pstruct = slop.to_struct('Foo')
    assert_kind_of Struct::Foo, pstruct
  end

  test 'returning missing options' do
    slop = Slop.new { on :a; on :b, :bar; on :c; }
    slop.parse %w[ -a ]

    assert_equal %w[ bar c ], slop.missing
  end

  test 'parsing an optspec and building options' do
    optspec = <<-SPEC
    ruby foo.rb [options]
    --
    v,verbose  enable verbose mode
    q,quiet   enable quiet mode
    debug      enable debug mode
    H          enable hax mode (srsly)
    n,name=    set your name
    -a,--age= set your age
    SPEC
    opts = Slop.optspec(optspec.gsub(/^\s+/, ''))
    opts.parse %w[ --verbose --name Lee ]

    assert_equal 'Lee', opts[:name]
    assert opts.verbose?
    assert_equal 'enable quiet mode', opts.options[:quiet].description
  end

  test "negative integers should not be processed as options and removed" do
    items = %w(-1)
    Slop.parse!(items)
    assert_equal %w(-1), items
  end

  test "options taking arguments should ignore argument that look like options (wut?)" do
    opts = Slop.new { on :v; on :foo, :optional => true, :default => 5, :as => Integer }
    opts.parse %w[ -c -v ]
    assert_equal 5, opts[:foo]
  end
end
