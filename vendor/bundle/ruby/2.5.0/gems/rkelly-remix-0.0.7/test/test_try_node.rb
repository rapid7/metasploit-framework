require File.dirname(__FILE__) + "/helper"

class TryNodeTest < NodeTestCase
  def test_failure
    var_foo = VarStatementNode.new([
      VarDeclNode.new('foo', AssignExprNode.new(NumberNode.new(10)))
    ])

    var_bar = VarStatementNode.new([
      VarDeclNode.new('bar', AssignExprNode.new(NumberNode.new(20)))
    ])

    var_baz = VarStatementNode.new([
      VarDeclNode.new('baz', AssignExprNode.new(NumberNode.new(69)))
    ])

    try_block = BlockNode.new(SourceElementsNode.new([var_baz]))
    catch_block = BlockNode.new(SourceElementsNode.new([var_bar]))
    finally_block = BlockNode.new(SourceElementsNode.new([var_foo]))

    node = TryNode.new(try_block, nil, nil, finally_block)
    assert_sexp([ :try,
                  [:block,
                    [[:var, [[:var_decl, :baz, [:assign, [:lit, 69]]]]]]
                  ],
                  nil,
                  nil,
                  [:block,
                    [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]
                  ]
    ], node)

    node = TryNode.new(try_block, 'a', catch_block)
    assert_sexp([ :try,
                  [:block,
                    [[:var, [[:var_decl, :baz, [:assign, [:lit, 69]]]]]]
                  ],
                  'a',
                  [:block,
                    [[:var, [[:var_decl, :bar, [:assign, [:lit, 20]]]]]]
                  ],
                  nil,
    ], node)

    node = TryNode.new(try_block, 'a', catch_block, finally_block)
    assert_sexp([ :try,
                  [:block,
                    [[:var, [[:var_decl, :baz, [:assign, [:lit, 69]]]]]]
                  ],
                  'a',
                  [:block,
                    [[:var, [[:var_decl, :bar, [:assign, [:lit, 20]]]]]]
                  ],
                  [:block,
                    [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]
                  ]
    ], node)
  end
end
