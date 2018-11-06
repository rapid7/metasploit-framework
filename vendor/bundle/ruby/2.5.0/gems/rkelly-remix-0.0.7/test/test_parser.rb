require File.dirname(__FILE__) + "/helper"

class ParserTest < Test::Unit::TestCase
  def setup
    @parser = RKelly::Parser.new
  end

  def test_birthday!
    assert_raises(RKelly::SyntaxError) do
      RKelly::Parser.new.parse "Happy birthday, tenderlove!"
    end
  end

  def test_array_access
    assert_sexp(
      [
        [:var,
          [[:var_decl, :a,
            [:assign, [:bracket_access, [:resolve, "foo"], [:lit, 10]]],
          ]]
        ]
      ],
      @parser.parse('var a = foo[10];'))
  end

  def test_function_expr_anon_no_args
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, "function", [], [:func_body, []]]
                  ]]]
                ]],
                @parser.parse("var foo = function() { }"))
  end

  def test_function_body_expr_anon_no_args
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, "function", [],
                      [:func_body,
                        [[:var, [[:var_decl, :a, [:assign, [:lit, 10]]]]]]
                      ]
                    ]
                  ]]]
                ]],
                @parser.parse("var foo = function() { var a = 10; }"))
  end

  def test_function_expr_anon_single_arg
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, "function", [[:param, "a"]], [:func_body, []]]
                  ]]]
                ]],
                @parser.parse("var foo = function(a) { }"))
  end

  def test_function_expr_anon
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, "function", [[:param, "a"], [:param, 'b']], [:func_body, []]]
                  ]]]
                ]],
                @parser.parse("var foo = function(a,b) { }"))
  end

  def test_function_expr_no_args
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, 'aaron', [], [:func_body, []]]
                  ]]]
                ]],
                @parser.parse("var foo = function aaron() { }"))
  end

  def test_function_expr_with_args
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:func_expr, 'aaron', [[:param, 'a'], [:param, 'b']], [:func_body, []]]
                  ]]]
                ]],
                @parser.parse("var foo = function aaron(a, b) { }"))
  end

  def test_labelled_statement
    assert_sexp([[:label, :foo, [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]],
                @parser.parse('foo: var x = 10;'))
    assert_sexp([[:label, :foo, [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]],
                @parser.parse('foo: var x = 10'))
  end

  def test_throw_statement
    assert_sexp([[:throw, [:lit, 10]]], @parser.parse('throw 10;'))
    assert_sexp([[:throw, [:lit, 10]]], @parser.parse('throw 10'))
  end

  def test_object_literal
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, :bar, [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { bar: 10 }'))
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, []]
                  ]]]
                ]],
                @parser.parse('var foo = { }'))
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, '"bar"'.to_sym, [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { "bar": 10 }'))
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, :"5", [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { 5: 10 }'))
  end

  def test_object_literal_getter
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:getter, :a, [:func_expr, nil, [], [:func_body, []]]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { get a() { } }'))
  end

  def test_object_literal_setter
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:setter, :a,
                      [:func_expr, nil, [[:param, 'foo']], [:func_body, []]]
                    ]]]
                  ]]]
                ]],
                @parser.parse('var foo = { set a(foo) { } }'))
  end

  def test_object_literal_multi
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [
                      [:property, :bar, [:lit, 10]],
                      [:property, :baz, [:lit, 1]]
                    ]]
                  ]]]
                ]],
                @parser.parse('var foo = { bar: 10, baz: 1 }'))
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [
                      [:property, :bar, [:lit, 10]],
                      [:property, :baz, [:lit, 1]]
                    ]]
                  ]]]
                ]],
                @parser.parse('var foo = { bar: 10, baz: 1, }'))
  end

  # ECMAScript 5.1 allows use of keywords for property names.

  def test_object_literal_with_keywords_as_property_names
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, :"var", [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { var: 10 }'))
  end

  def test_object_literal_with_literal_as_property_name
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, :"null", [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { null: 10 }'))
  end

  def test_object_literal_with_reserved_keyword_as_property_name
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:property, :"class", [:lit, 10]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { class: 10 }'))
  end

  def test_object_literal_getter_with_keyword_as_getter_name
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:getter, :if, [:func_expr, nil, [], [:func_body, []]]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { get if() { } }'))
  end

  def test_object_literal_setter_with_keyword_as_setter_name
    assert_sexp(
                [[:var,
                  [[:var_decl, :foo, [:assign,
                    [:object, [[:setter, :return, [:func_expr, nil, [[:param, "v"]], [:func_body, []]]]]]
                  ]]]
                ]],
                @parser.parse('var foo = { set return(v) { } }'))
  end

  def test_dot_access_with_keyword
    assert_sexp([[:expression,
                  [:dot_access,
                    [:resolve, "bar"],
                    'var',
                  ]
                ]],
                @parser.parse('bar.var;'))
  end

  def test_dot_access_with_keyword_on_function_call
    assert_sexp([[:expression,
                  [:dot_access,
                    [:function_call, [:resolve, "bar"], [:args, []]],
                    'var',
                  ]
                ]],
                @parser.parse('bar().var;'))
  end


  def test_this
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign, [:this]]]]]],
                @parser.parse('var foo = this;')
               )
  end

  def test_array_literal
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [[:element, [:lit, 1]]]]
                ]]]]],
                @parser.parse('var foo = [1];')
               )
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [
                    nil,
                    nil,
                    [:element, [:lit, 1]]
                  ]]
                ]]]]],
                @parser.parse('var foo = [,,1];')
               )
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [
                    [:element, [:lit, 1]],
                    nil,
                    nil,
                    [:element, [:lit, 2]]
                  ]]
                ]]]]],
                @parser.parse('var foo = [1,,,2];')
               )
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [
                    [:element, [:lit, 1]],
                    nil,
                    nil,
                  ]]
                ]]]]],
                @parser.parse('var foo = [1,,,];')
               )
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [
                  ]]
                ]]]]],
                @parser.parse('var foo = [];')
               )
    assert_sexp(
                [[:var, [[:var_decl, :foo, [:assign,
                  [:array, [
                    nil, nil
                  ]]
                ]]]]],
                @parser.parse('var foo = [,,];')
               )
  end

  def test_primary_expr_paren
    assert_sexp(
      [[:var,
        [[:var_decl, :a, [:assign, [:lit, 10]]]]
      ]],
      @parser.parse('var a = (10);'))
  end

  def test_expression_statement
    assert_sexp(
                [[:expression, [:dot_access, [:resolve, "foo"], "bar"]]],
                @parser.parse('foo.bar;')
               )
    assert_sexp(
                [[:expression, [:dot_access, [:resolve, "foo"], "bar"]]],
                @parser.parse('foo.bar')
               )
  end

  def test_expr_comma
    assert_sexp([[:expression, [:comma,
                [:op_equal, [:resolve, 'i'], [:lit, 10]],
                [:op_equal, [:resolve, 'j'], [:lit, 11]]]]],
                @parser.parse('i = 10, j = 11;')
               )
  end

  def test_op_plus_equal
    assert_sexp([[:expression, [:op_plus_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i += 10'))
  end

  def test_op_minus_equal
    assert_sexp([[:expression, [:op_minus_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i -= 10'))
  end

  def test_op_multiply_equal
    assert_sexp([[:expression, [:op_multiply_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i *= 10'))
  end

  def test_op_divide_equal
    assert_sexp([[:expression, [:op_divide_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i /= 10'))
  end

  def test_op_lshift_equal
    assert_sexp([[:expression, [:op_lshift_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i <<= 10'))
  end

  def test_op_rshift_equal
    assert_sexp([[:expression, [:op_rshift_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i >>= 10'))
  end

  def test_op_urshift_equal
    assert_sexp([[:expression, [:op_urshift_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i >>>= 10'))
  end

  def test_op_and_equal
    assert_sexp([[:expression, [:op_and_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i &= 10'))
  end

  def test_op_xor_equal
    assert_sexp([[:expression, [:op_xor_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i ^= 10'))
  end

  def test_op_or_equal
    assert_sexp([[:expression, [:op_or_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i |= 10'))
  end

  def test_op_mod_equal
    assert_sexp([[:expression, [:op_mod_equal, [:resolve, 'i'], [:lit, 10]]]],
                @parser.parse('i %= 10'))
  end

  def test_bracket_access_no_bf
    assert_sexp(
      [[:expression,
            [:bracket_access, [:resolve, "foo"], [:lit, 10]],
      ]],
      @parser.parse('foo[10];'))
  end

  def test_new_member_expr_no_bf
    assert_sexp(
      [[:expression,
            [:new_expr, [:resolve, "foo"], [:args, []]],
      ]],
      @parser.parse('new foo();'))
  end

  def test_resolve_function_call
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:function_call, [:resolve, "bar"], [:args, []]]]
                  ]]
                ]],
                @parser.parse('var x = bar();'))
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:function_call, [:resolve, "bar"], [:args, [[:lit, 10]]]]]
                  ]]
                ]],
                @parser.parse('var x = bar(10);'))
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:function_call, [:resolve, "bar"], [:args, [
                      [:resolve, 'a'],
                      [:lit, 10]
                    ]]]]
                  ]]
                ]],
                @parser.parse('var x = bar(a,10);'))
  end

  def test_function_no_bf
    assert_sexp([[:expression,
                  [:function_call, [:resolve, "bar"], [:args, []]]
                ]],
                @parser.parse('bar();'))
  end

  def test_function_on_function_no_bf
    assert_sexp([[:expression,
                  [:function_call,
                    [:function_call, [:resolve, "bar"], [:args, []]],
                    [:args, []]
                  ]
                ]],
                @parser.parse('bar()();'))
  end

  def test_bracket_on_function_no_bf
    assert_sexp([[:expression,
                  [:bracket_access,
                    [:function_call, [:resolve, "bar"], [:args, []]],
                    [:lit, 1],
                  ]
                ]],
                @parser.parse('bar()[1];'))
  end

  def test_dot_on_function_no_bf
    assert_sexp([[:expression,
                  [:dot_access,
                    [:function_call, [:resolve, "bar"], [:args, []]],
                    'baz',
                  ]
                ]],
                @parser.parse('bar().baz;'))
  end

  def test_new_expr_no_bf
    assert_sexp([[:expression, [:new_expr, [:resolve, 'foo'], [:args, []]]]],
      @parser.parse('new foo;'))
  end

  def test_new_expr
    assert_sexp([[:var, [[:var_decl, :a, [:assign, [:new_expr, [:resolve, 'foo'], [:args, []]]]]]]],
      @parser.parse('var a = new foo;'))
  end

  def test_postfix_expr
    assert_sexp([[:var,
                [[:var_decl,
                  :x,
                  [:assign, [:postfix, [:lit, 10], '++']]]]]],
                  @parser.parse('var x = 10++;'))
    assert_sexp([[:var,
                [[:var_decl,
                  :x,
                  [:assign, [:postfix, [:lit, 10], '--']]]]]],
                  @parser.parse('var x = 10--;'))
  end

  def test_postfix_expr_no_bf
    assert_sexp([[:expression,
                  [:postfix, [:lit, 10], '++']]],
                  @parser.parse('10++;'))
    assert_sexp([[:expression,
                  [:postfix, [:lit, 10], '--']]],
                  @parser.parse('10--;'))
  end

  def test_unary_delete
    assert_sexp([[:expression, [:delete, [:resolve, 'foo']]]],
                @parser.parse('delete foo;'))
  end

  def test_unary_void
    assert_sexp([[:expression, [:void, [:resolve, 'foo']]]],
                @parser.parse('void foo;'))
  end

  def test_unary_typeof
    assert_sexp([[:expression, [:typeof, [:resolve, 'foo']]]],
                @parser.parse('typeof foo;'))
  end

  def test_unary_prefix
    assert_sexp([[:expression, [:prefix, [:lit, 10], '++']]],
                @parser.parse('++10;'))
    assert_sexp([[:expression, [:prefix, [:lit, 10], '--']]],
                @parser.parse('--10;'))
  end

  def test_unary_plus
    assert_sexp([[:expression, [:u_plus, [:lit, 10]]]],
                @parser.parse('+10;'))
  end

  def test_unary_minus
    assert_sexp([[:expression, [:u_minus, [:lit, 10]]]],
                @parser.parse('-10;'))
  end

  def test_unary_bitwise_not
    assert_sexp([[:expression, [:bitwise_not, [:lit, 10]]]],
                @parser.parse('~10;'))
  end

  def test_unary_logical_not
    assert_sexp([[:expression, [:not, [:lit, 10]]]],
                @parser.parse('!10;'))
  end

  def test_multiply
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:multiply, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 * 10;'))
  end

  def test_multiply_no_bf
    assert_sexp([[:expression, [:multiply, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 * 10;'))
  end

  def test_divide
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:divide, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 / 10;'))
  end

  def test_divide_no_bf
    assert_sexp([[:expression, [:divide, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 / 10;'))
  end

  def test_modulus
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:modulus, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 % 10;'))
  end

  def test_modulus_no_bf
    assert_sexp([[:expression, [:modulus, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 % 10;'))
  end

  def test_add
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:add, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 + 10;'))
  end

  def test_add_no_bf
    assert_sexp([[:expression, [:add, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 + 10;'))
  end

  def test_subtract
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:subtract, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 - 10;'))
  end

  def test_subtract_no_bf
    assert_sexp([[:expression, [:subtract, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 - 10;'))
  end

  def test_lshift
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:lshift, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 << 10;'))
  end

  def test_lshift_no_bf
    assert_sexp([[:expression, [:lshift, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 << 10;'))
  end

  def test_rshift
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:rshift, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 >> 10;'))
  end

  def test_rshift_no_bf
    assert_sexp([[:expression, [:rshift, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 >> 10;'))
  end

  def test_urshift
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:urshift, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 >>> 10;'))
  end

  def test_urshift_no_bf
    assert_sexp([[:expression, [:urshift, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 >>> 10;'))
  end

  def test_less
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:less, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 < 10;'))
  end

  def test_less_no_bf
    assert_sexp([[:expression, [:less, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 < 10;'))
  end

  def test_less_no_in
    assert_sexp(
      for_loop_sexp([:less, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo < 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_greater
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:greater, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 > 10;'))
  end

  def test_greater_no_bf
    assert_sexp([[:expression, [:greater, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 > 10;'))
  end

  def test_greater_no_in
    assert_sexp(
      for_loop_sexp([:greater, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo > 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_less_or_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:less_or_equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 <= 10;'))
  end

  def test_less_or_equal_no_bf
    assert_sexp([[:expression, [:less_or_equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 <= 10;'))
  end

  def test_less_or_equal_no_in
    assert_sexp(
      for_loop_sexp([:less_or_equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo <= 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_greater_or_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:greater_or_equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 >= 10;'))
  end

  def test_greater_or_equal_no_bf
    assert_sexp([[:expression, [:greater_or_equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 >= 10;'))
  end

  def test_greater_or_equal_no_in
    assert_sexp(
      for_loop_sexp([:greater_or_equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo >= 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_instance_of
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:instance_of, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 instanceof 10;'))
  end

  def test_instanceof_no_bf
    assert_sexp([[:expression, [:instance_of, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 instanceof 10;'))
  end

  def test_instanceof_no_in
    assert_sexp(for_loop_sexp([:instance_of, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo instanceof 10; foo < 10; foo++) { var x = 10; }'))
  end

  def test_equal_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 == 10;'))
  end

  def test_equal_equal_no_bf
    assert_sexp([[:expression, [:equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 == 10;'))
  end

  def test_equal_equal_no_in
    assert_sexp(
      for_loop_sexp([:equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo == 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_not_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:not_equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 != 10;'))
  end

  def test_not_equal_no_bf
    assert_sexp([[:expression, [:not_equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 != 10;'))
  end

  def test_not_equal_no_in
    assert_sexp(
      for_loop_sexp([:not_equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo != 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_strict_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:strict_equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 === 10;'))
  end

  def test_strict_equal_no_bf
    assert_sexp([[:expression, [:strict_equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 === 10;'))
  end

  def test_strict_equal_no_in
    assert_sexp(
      for_loop_sexp([:strict_equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo === 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_not_strict_equal
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:not_strict_equal, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 !== 10;'))
  end

  def test_not_strict_equal_no_bf
    assert_sexp([[:expression, [:not_strict_equal, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 !== 10;'))
  end

  def test_not_strict_equal_no_in
    assert_sexp(
      for_loop_sexp([:not_strict_equal, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo !== 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_bit_and
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:bit_and, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 & 10;'))
  end

  def test_bit_and_no_bf
    assert_sexp([[:expression, [:bit_and, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 & 10;'))
  end

  def test_bit_and_no_in
    assert_sexp(
      for_loop_sexp([:bit_and, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo & 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_bit_xor
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:bit_xor, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 ^ 10;'))
  end

  def test_bit_xor_no_bf
    assert_sexp([[:expression, [:bit_xor, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 ^ 10;'))
  end

  def test_bit_xor_no_in
    assert_sexp(
      for_loop_sexp([:bit_xor, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo ^ 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_bit_or
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:bit_or, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 | 10;'))
  end

  def test_bit_or_no_bf
    assert_sexp([[:expression, [:bit_or, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 | 10;'))
  end

  def test_bit_or_no_in
    assert_sexp(
      for_loop_sexp([:bit_or, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo | 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_and
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:and, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 && 10;'))
  end

  def test_and_no_bf
    assert_sexp([[:expression, [:and, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 && 10;'))
  end

  def test_and_no_in
    assert_sexp(
      for_loop_sexp([:and, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo && 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_or
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:or, [:lit, 5], [:lit, 10]]]
                  ]]
                ]],
                @parser.parse('var x = 5 || 10;'))
  end

  def test_or_no_bf
    assert_sexp([[:expression, [:or, [:lit, 5], [:lit, 10]] ]],
                @parser.parse('5 || 10;'))
  end

  def test_or_no_in
    assert_sexp(
      for_loop_sexp([:or, [:resolve, 'foo'], [:lit, 10]]),
      @parser.parse('for(foo || 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_conditional_expr
    assert_sexp([
      var_sexp('x', [:conditional, [:less, [:lit, 5], [:lit, 10]], [:lit, 20], [:lit, 30]])
      ],
      @parser.parse('var x = 5 < 10 ? 20 : 30;')
               )
  end

  def test_conditional_expr_no_bf
    assert_sexp([[:expression,
        [:conditional, [:less, [:lit, 5], [:lit, 10]], [:lit, 20], [:lit, 30]]
      ]],
      @parser.parse('5 < 10 ? 20 : 30;')
               )
  end

  def test_for_expr_comma
    @parser.parse('for(y = 20, x = 10; foo < 10; foo++) {}')
    assert_sexp(
      for_loop_sexp([:comma,
                    [:op_equal, [:resolve, 'y'], [:lit, 20]],
                    [:op_equal, [:resolve, 'x'], [:lit, 10]]]
                    ),
      @parser.parse('for(y = 20, x = 10; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_conditional_expr_no_in
    assert_sexp(
      for_loop_sexp([:conditional, [:less, [:lit, 5], [:lit, 10]], [:lit, 20], [:lit, 30]]),
      @parser.parse('for(5 < 10 ? 20 : 30; foo < 10; foo++) { var x = 10; }')
               )
  end

  def test_block_node
    assert_sexp([[:block, []]], @parser.parse('{ }'))
    assert_sexp([[:block, [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]]],
                @parser.parse('{ var foo = 10; }'))

    assert_sexp([
                [:block, [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]]],
                [:var, [[:var_decl, :bax, [:assign, [:lit, 20]]]]],
                ],
                @parser.parse('{ var foo = 10 } var bax = 20;'))
  end

  def test_if_no_else
    assert_sexp([[:if,
                [:and, [:lit, 5], [:lit, 10]],
                [:var, [[:var_decl, :foo, [:assign, [:lit, 20]]]]],
    ]], @parser.parse('if(5 && 10) var foo = 20;'))
  end

  def test_if_else
    assert_sexp([[:if,
                [:and, [:lit, 5], [:lit, 10]],
                [:var, [[:var_decl, :foo, [:assign, [:lit, 20]]]]],
                [:var, [[:var_decl, :bar, [:assign, [:lit, 5]]]]],
    ]], @parser.parse(' if(5 && 10) var foo = 20; else var bar = 5; '))
  end

  def test_if_comma
    assert_sexp(
                [[:if,
                  [:comma,
                   [:op_equal, [:resolve, "i"], [:lit, 10]],
                   [:op_equal, [:resolve, "j"], [:lit, 11]]],
                  [:block, []]]],
                @parser.parse('if(i = 10, j = 11) { }')
               )
  end

  def test_in
    assert_sexp([[:var,
                  [[:var_decl, :x, [:assign,
                    [:in, [:lit, 0], [:resolve, "foo"]]
                  ]]]
                ]],
                @parser.parse('var x = 0 in foo;'))
  end

  def test_in_no_bf
    assert_sexp([[:expression, [:in, [:lit, 0], [:resolve, "foo"]]]],
                @parser.parse('0 in foo;'))
  end

  def test_do_while
    assert_sexp([[:do_while, [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]],
                  [:true]]],
                @parser.parse('do var x = 10; while(true);'))
    assert_sexp([[:do_while, [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]],
                  [:true]]],
                @parser.parse('do var x = 10; while(true)'))
  end

  def test_while
    assert_sexp([[:while,
                  [:true],
                  [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]],
                ]],
                @parser.parse('while(true) var x = 10;'))
  end

  def test_for_with_semi
    assert_sexp([[:for, nil, nil, nil,
                [:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]],
    ]], @parser.parse('for( ; ; ) var x = 10;'))

    assert_sexp([[:for,
                [:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]],
                [:less, [:resolve, 'foo'], [:lit, 10]],
                [:postfix, [:resolve, 'foo'], '++'],
                [:block, [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]]]
    ], @parser.parse('for(var foo = 10; foo < 10; foo++) { var x = 10; }'))
    assert_sexp([[:for,
                [:op_equal, [:resolve, 'foo'], [:lit, 10]],
                [:less, [:resolve, 'foo'], [:lit, 10]],
                [:postfix, [:resolve, 'foo'], '++'],
                [:block, [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]]]
    ], @parser.parse('for(foo = 10; foo < 10; foo++) { var x = 10; }'))

    assert_sexp(for_loop_sexp([:var, [[:var_decl, :x, [:assign, [:lit, 10]]],
                              [:var_decl, :y, [:assign, [:lit, 20]]]]]),
    @parser.parse('for(var x = 10, y = 20; foo < 10; foo++) { var x = 10; }'))

    assert_sexp(for_loop_sexp([:var, [[:var_decl, :foo, nil]]]),
    @parser.parse('for(var foo; foo < 10; foo++) { var x = 10; }'))
  end

  def test_for_expr_in_expr
    assert_sexp(
                for_in_sexp([:resolve, 'foo'], [:resolve, 'bar']),
                @parser.parse('for(foo in bar) { var x = 10; }')
               )
  end

  def test_for_var_ident_in_expr
    assert_sexp(
                for_in_sexp([:var_decl, :foo, nil], [:resolve, 'bar']),
                @parser.parse('for(var foo in bar) { var x = 10; }')
               )
  end

  def test_for_var_ident_init_in_expr
    assert_sexp(
                for_in_sexp([:var_decl, :foo, [:assign,[:lit, 10]]], [:resolve, 'bar']),
                @parser.parse('for(var foo = 10 in bar) { var x = 10; }')
               )
  end

  def test_try_finally
    assert_sexp([[ :try,
                  [:block,
                    [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]
                  ],
                  nil,
                  nil,
                  [:block,
                    [[:var, [[:var_decl, :x, [:assign, [:lit, 20]]]]]]
                  ]
    ]],
                @parser.parse('try { var x = 10; } finally { var x = 20; }'))
  end

  def test_try_catch
    assert_sexp([[ :try,
                  [:block,
                    [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]
                  ],
                  'a',
                  [:block,
                    [[:var, [[:var_decl, :x, [:assign, [:lit, 20]]]]]]
                  ],
                  nil,
    ]],
                @parser.parse('try { var x = 10; } catch(a) { var x = 20; }'))
  end

  def test_try_catch_finally
    assert_sexp([[ :try,
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
    ]],
                @parser.parse('try { var baz = 69; } catch(a) { var bar = 20; } finally { var foo = 10; }'))
  end

  def test_with
    assert_sexp([[:with, [:resolve, 'o'], [:expression, [:resolve, 'x']]]],
                @parser.parse('with (o) x;')
               )
  end

  def test_switch_no_case
    assert_sexp([[:switch, [:resolve, 'o'], [:case_block, []]]],
                @parser.parse('switch(o) { }')
               )
  end

  def test_switch_case_no_statement
    assert_sexp([[:switch, [:resolve, 'o'], [:case_block, [[:case, [:resolve, 'j'], []]]]]],
                @parser.parse('switch(o) { case j: }')
               )
  end

  def test_switch_case
    assert_sexp([[:switch, [:resolve, 'o'],
                  [:case_block,
                    [[:case, [:resolve, 'j'], [[:expression, [:resolve, 'foo']]]]]
                  ]
                ]],
                @parser.parse('switch(o) { case j: foo; }')
               )
  end

  def test_switch_case_case
    assert_sexp([[:switch, [:resolve, 'o'],
                  [:case_block,[
                    [:case, [:resolve, 'j'], [[:expression, [:resolve, 'foo']]]],
                    [:case, [:resolve, 'k'], [[:expression, [:resolve, 'bar']]]],
                  ]]
                ]],
                @parser.parse('switch(o) { case j: foo; case k: bar; }')
               )
  end

  def test_switch_default
    assert_sexp([[:switch, [:resolve, 'o'],
                  [:case_block,[
                    [:case, nil, [[:expression, [:resolve, 'bar']]]],
                  ]]
                ]],
                @parser.parse('switch(o) { default: bar; }')
               )
  end

  def test_switch_default_no_expr
    assert_sexp([[:switch, [:resolve, 'o'],
                  [:case_block,[
                    [:case, nil, []],
                  ]]
                ]],
                @parser.parse('switch(o) { default: }')
               )
  end

  def test_function_call_on_function
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:function_call,
                      [:function_call, [:resolve, "bar"], [:args, []]],
                    [:args, []]]]
                  ]]
                ]],
                @parser.parse('var x = bar()();'))
  end

  def test_bracket_on_function
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:bracket_access,
                      [:function_call, [:resolve, "bar"], [:args, []]],
                      [:lit, 1]
                    ]]
                  ]]
                ]],
                @parser.parse('var x = bar()[1];'))
  end

  def test_dot_on_function
    assert_sexp([[:var,
                  [[:var_decl,
                    :x,
                    [:assign, [:dot_access,
                      [:function_call, [:resolve, "bar"], [:args, []]],
                      'baz'
                    ]]
                  ]]
                ]],
                @parser.parse('var x = bar().baz;'))
  end

  def test_dot_access
    assert_sexp(
      [[:var,
        [[:var_decl, :a, [:assign, [:dot_access, [:resolve, "foo"], "bar"]]]]
      ]],
      @parser.parse('var a = foo.bar;'))
  end

  def test_new_member_expr
    assert_sexp(
      [[:var,
        [[:var_decl, :a,
          [:assign, [:new_expr, [:resolve, "foo"], [:args, []]]]
        ]]
      ]],
      @parser.parse('var a = new foo();'))
  end

  def test_empty_statement
    assert_sexp(
      [
        [:const, [[:const_decl, :foo, [:assign, [:lit, 10]]]]],
        [:empty]
      ],
      @parser.parse('const foo = 10; ;')
    )
  end

  def test_debugger_statement
    assert_sexp(
      [ [:empty] ],
      @parser.parse('debugger;')
    )
    assert_sexp(
      [ [:empty] ],
      @parser.parse('debugger')
    )
  end

  def test_function_decl
    assert_sexp([[:func_decl, 'foo', [], [:func_body, []]]],
                @parser.parse('function foo() { }'))
  end

  def test_function_decl_params
    assert_sexp([[:func_decl, 'foo', [[:param, 'a']], [:func_body, []]]],
                @parser.parse('function foo(a) { }'))
  end

  def test_const_statement
    assert_sexp(
      [[:const, [[:const_decl, :foo, [:assign, [:lit, 10]]]]]],
      @parser.parse('const foo = 10;')
    )
  end

  def test_const_decl_list
    assert_sexp(
      [[:const,
        [
          [:const_decl, :foo, [:assign, [:lit, 10]]],
          [:const_decl, :bar, [:assign, [:lit, 1]]],
      ]]],
      @parser.parse('const foo = 10, bar = 1;')
    )
  end

  def test_const_decl_no_init
    assert_sexp(
      [[:const, [[:const_decl, :foo, nil]]]],
      @parser.parse('const foo;')
    )
  end

  def test_const_statement_error
    assert_sexp(
      [[:const, [[:const_decl, :foo, [:assign, [:lit, 10]]]]]],
      @parser.parse('const foo = 10')
    )
  end

  def test_variable_statement
    assert_sexp(
      [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]],
      @parser.parse('var foo = 10;')
    )
  end

  def test_variable_declaration_no_init
    assert_sexp(
      [[:var, [[:var_decl, :foo, nil]]]],
      @parser.parse('var foo;')
    )
  end

  def test_variable_declaration_nil_init
    assert_sexp(
      [[:var, [[:var_decl, :foo, [:assign, [:nil]]]]]],
      @parser.parse('var foo = null;')
    )
  end

  def test_variable_statement_no_semi
    assert_sexp(
      [[:var, [[:var_decl, :foo, [:assign, [:lit, 10]]]]]],
      @parser.parse('var foo = 10')
    )
  end

  def test_return_statement
    assert_sexp(
      [[:return]],
      @parser.parse('return;')
    )
    assert_sexp(
      [[:return]],
      @parser.parse('return')
    )
    assert_sexp(
      [[:return, [:lit, 10]]],
      @parser.parse('return 10;')
    )
    assert_sexp(
      [[:return, [:lit, 10]]],
      @parser.parse('return 10')
    )
  end

  def test_break_statement
    assert_sexp([[:break]], @parser.parse('break;'))
    assert_sexp([[:break]], @parser.parse('break'))
    assert_sexp([[:break, 'foo']], @parser.parse('break foo;'))
    assert_sexp([[:break, 'foo']], @parser.parse('break foo'))
  end

  def test_continue_statement
    assert_sexp([[:continue]], @parser.parse('continue;'))
    assert_sexp([[:continue]], @parser.parse('continue'))
    assert_sexp([[:continue, 'foo']], @parser.parse('continue foo;'))
    assert_sexp([[:continue, 'foo']], @parser.parse('continue foo'))
  end

  def test_variable_declaration_list
    assert_sexp(
      [[:var,
        [
          [:var_decl, :foo, [:assign, [:lit, 10]]],
          [:var_decl, :bar, [:assign, [:lit, 1]]],
      ]]],
      @parser.parse('var foo = 10, bar = 1;')
    )
  end

  def assert_sexp(expected, node)
    assert_equal(expected, node.to_sexp)
  end

  def var_sexp(variable_name, val = [:lit, 10])
    [:var, [[:var_decl, variable_name.to_sym, [:assign, val]]]]
  end

  def for_in_sexp(variable, list)
    [[:for_in, variable, list, [:block, [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]]]]
  end

  def for_loop_sexp(init, test = [:less, [:resolve, 'foo'], [:lit, 10]], exec = [:postfix, [:resolve, 'foo'], '++'])
    [[:for, init, test, exec, [:block, [[:var, [[:var_decl, :x, [:assign, [:lit, 10]]]]]]]]]
  end
end
