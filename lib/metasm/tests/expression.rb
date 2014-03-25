#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm'

class TestExpression < Test::Unit::TestCase
  E = Metasm::Expression
  def test_encode
    assert_equal("\x04\0\0\0", E[4].encode(:u32, :little).data)
  end

  def test_numeric
    assert_equal(5, E[4, :+, 1].reduce)
  end

  def test_reduce
    assert_equal(0, E[:a, :-, :a].reduce)
    assert_equal(0, E[:a, :^, :a].reduce)

    assert_equal(E[:a, :^, 3], E[[1, :^, :a], :^, 2].reduce)
    assert_equal(E[:a], E[[:b, :^, :a], :^, :b].reduce)

    assert_equal(E[:a, :+, 2], E[:b, :+, [:a, :-, [4, :+, [:b, :-, 6]]]].reduce)
    assert_equal(E[:a, :&, 0xff00], E[[[:a, :>>, 8], :&, 0xff], :<<, 8].reduce)

    assert_equal(E[[:a, :>>, 1], :&, 0xff0], E[[[:a, :>>, 5], :&, 0xff], :<<, 4].reduce)

    assert_equal(0, E[[:a, :&, 0xff00], :&, [:b, :&, 0xff]].reduce)
    assert_equal(0, E[[:a, :&, 0xff], :>>, 8].reduce)

    assert_equal(E[:a, :&, 0xffff], E[[:a, :&, 0x3333], :|, [[:a, :&, 0x8888], :+, [:a, :&, 0x4444]]].reduce)

    assert_equal(E[:a, :&, 0xff], E[[:a, :|, [:b, :&, 0xff00]], :&, 0xff].reduce)

    assert_equal(1, E[[2, :>, 1], :'||', [:a, :<=, :b]].reduce)
    assert_equal(0, E[[:a, :>, :b], :'&&', [1, :>, 2]].reduce)

    assert_equal(E[:a, :>, :b], E[[:'!', [:a, :<=, :b]], :==, 1].reduce)
  end

  def test_pattern
    pat = E[:a, :+, [:b, :&, 0xffff]].match(E['a', :|, 'b'], 'a', 'b')
    assert_equal(false, pat)

    pat = E[:a, :+, [:b, :&, 0xffff]].match(E['a', :+, 'b'], 'a', 'b')
    assert_equal(:a, pat['a'])
    p2 = pat['b'].match(E[:a, :b, :c], :a, :b, :c)
    assert_equal(0xffff, p2[:c])
    assert_equal(:&, p2[:b])
  end
end
