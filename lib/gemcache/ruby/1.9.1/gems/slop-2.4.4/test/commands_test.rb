require 'helper'

class CommandsTest < TestCase
  test 'creating commands' do
    slop = Slop.new do
      command :foo do on :f, :foo, 'foo option' end
      command :bar do on :f, :foo; on :b, :bar, true end
    end

    slop.commands.each_value do |command|
      assert_kind_of Slop, command
    end

    assert 'foo option', slop.commands[:foo].options[:foo].description

    slop.parse %w/bar --bar baz/
    assert 'baz', slop.commands[:bar][:bar]
    assert_nil slop.commands['bar']
  end

  test 'repeating existing commands' do
    slop = Slop.new
    assert slop.command :foo
    assert_raises(ArgumentError) { slop.command :foo }
  end

  test 'commands inheriting options' do
    slop = Slop.new :strict do
      command :foo do end
    end
    assert slop.commands[:foo].instance_variable_get(:@strict)
  end

  test 'commands setting options' do
    slop = Slop.new :strict => false do
      command :foo, :strict => true do end
    end
    assert slop.commands[:foo].instance_variable_get(:@strict)
  end

  test 'inception' do
    slop = Slop.new do
      command(:foo) { command(:bar) { command(:baz) { on :f, 'D:' } } }
    end
    desc = slop.commands[:foo].commands[:bar].commands[:baz].options[:f].description
    assert_equal 'D:', desc
  end

  test 'commands with banners' do
    slop = Slop.new do
      command(:foo, :banner => 'bar') { }
      command(:bar) { banner 'bar' }
    end
    assert_equal 'bar', slop.commands[:foo].banner
    assert_equal 'bar', slop.commands[:bar].banner
  end

  test 'executing on_empty on separate commands' do
    incmd = inslop = false
    slop = Slop.new do
      command(:foo) { on(:bar) {}; on_empty { incmd = true }}
      on_empty { inslop = true }
    end
    slop.parse %w//
    assert inslop
    refute incmd
    inslop = false
    slop.parse %w/foo/
    assert incmd
    refute inslop
  end

  test 'executing blocks' do
    foo = bar = nil
    slop = Slop.new
    slop.command :foo do
      on :v, :verbose
      execute { |o, a| foo = o.verbose? }
    end
    slop.command :bar do
      on :v, :verbose
      execute { |o, a| bar = o.verbose? }
    end
    slop.parse %w[ foo --verbose ]

    assert foo
    refute bar
  end

  test 'executing blocks and command arguments' do
    opts = args = nil
    slop = Slop.new
    slop.command :foo do
      execute do |o, a|
        opts = o
        args = a
      end
    end
    slop.parse %w[ foo bar baz ]

    assert_equal %w[ bar baz ], args
    assert_kind_of Slop, opts
  end

  test 'executing nested commands' do
    args = nil
    slop = Slop.new
    slop.command :foo do
      command :bar do
        execute { |o, a| args = a }
      end
    end
    slop.parse %w[ foo bar baz ]

    assert_equal %w[ baz ], args
  end

  test 'aliases' do
    slop = Slop.new
    slop.command :foo, :alias => :bar
    slop.command :baz, :aliases => [:lorem, :ipsum]

    assert_equal [:bar], slop.commands[:foo].aliases
    assert_equal [:lorem, :ipsum], slop.commands[:baz].aliases

    assert_raises(ArgumentError) { slop.command :lorem }
  end

  test 'command completion' do
    foo = bar = bara = nil
    slop = Slop.new
    slop.command(:foo) { execute { foo = true } }
    slop.parse %w[ fo ]
    assert foo

    slop.command(:bar) { execute { bar = true } }
    slop.command(:bara) { execute { bara = true } }
    slop.parse %w[ bar ]
    assert bar
    refute bara
  end

  test 'ambiguous command completion' do
    io = StringIO.new
    slop = Slop.new(:io => io)
    slop.command :bar
    slop.command :baz
    slop.parse %w[ ba ]
    assert_equal "Command 'ba' is ambiguous:\n  bar, baz\n", io.string
  end
end