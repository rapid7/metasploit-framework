# frozen_string_literal: true

RSpec.describe YARD::Parser::Ruby::RubyParser do
  def stmt(stmt)
    YARD::Parser::Ruby::RubyParser.new(stmt, nil).parse.root.first
  end

  def stmts(stmts)
    YARD::Parser::Ruby::RubyParser.new(stmts, nil).parse.root
  end

  def tokenize(stmt)
    YARD::Parser::Ruby::RubyParser.new(stmt, nil).parse.tokens
  end

  describe "#parse" do
    it "gets comment line numbers" do
      s = stmt <<-eof
        # comment
        # comment
        # comment
        def method; end
      eof
      expect(s.comments).to eq "comment\ncomment\ncomment"
      expect(s.comments_range).to eq(1..3)

      s = stmt <<-eof

        # comment
        # comment
        def method; end
      eof
      expect(s.comments).to eq "comment\ncomment"
      expect(s.comments_range).to eq(2..3)

      s = stmt <<-eof
        # comment
        # comment

        def method; end
      eof
      expect(s.comments).to eq "comment\ncomment"
      expect(s.comments_range).to eq(1..2)

      s = stmt <<-eof
        # comment
        def method; end
      eof
      expect(s.comments).to eq "comment"
      expect(s.comments_range).to eq(1..1)

      s = stmt <<-eof
        def method; end # comment
      eof
      expect(s.comments).to eq "comment"
      expect(s.comments_range).to eq(1..1)
    end

    it "only looks up to two lines back for comments" do
      s = stmts <<-eof
        # comments

        # comments

        def method; end
      eof
      expect(s[1].comments).to eq "comments"

      s = stmts <<-eof
        # comments


        def method; end
      eof
      expect(s[1].comments).to eq nil

      ss = stmts <<-eof
        # comments


        def method; end

        # hello
        def method2; end
      eof
      expect(ss[1].comments).to eq nil
      expect(ss[2].comments).to eq 'hello'
    end

    it "handles block comment followed by line comment" do
      ss = stmts <<-eof
# comments1

=begin
comments2
=end
# comments3
def hello; end
eof
      expect(ss.last.comments).to eq "comments3"
    end

    it "handles block comment followed by block comment" do
      ss = stmts <<-eof
=begin
comments1
=end
=begin
comments2
=end
def hello; end
eof
      expect(ss.last.comments.strip).to eq "comments2"
    end

    it "handles 1.9 lambda syntax with args" do
      src = "->(a,b,c=1,*args,&block) { hello_world }"
      expect(stmt(src).source).to eq src
    end

    it "handles 1.9 lambda syntax" do
      src = "-> { hello_world }"
      expect(stmt(src).source).to eq src
    end

    it "handles standard lambda syntax" do
      src = "lambda { hello_world }"
      expect(stmt(src).source).to eq src
    end

    it "throws a ParserSyntaxError on invalid code" do
      expect { stmt("Foo, bar.") }.to raise_error(YARD::Parser::ParserSyntaxError)
    end

    it "handles bare hashes as method parameters" do
      src = "command :a => 1, :b => 2, :c => 3"
      expect(stmt(src).jump(:command)[1].source).to eq ":a => 1, :b => 2, :c => 3"

      src = "command a: 1, b: 2, c: 3"
      expect(stmt(src).jump(:command)[1].source).to eq "a: 1, b: 2, c: 3"
    end

    it "handles source for hash syntax" do
      src = "{ :a => 1, :b => 2, :c => 3 }"
      expect(stmt(src).jump(:hash).source).to eq "{ :a => 1, :b => 2, :c => 3 }"
    end

    it "handles an empty hash" do
      expect(stmt("{}").jump(:hash).source).to eq "{}"
    end

    it "new hash label syntax should show label without colon" do
      ast = stmt("{ a: 1 }").jump(:label)
      expect(ast[0]).to eq "a"
      expect(ast.source).to eq "a:"
    end

    it "handles begin/rescue blocks" do
      ast = stmt("begin; X; rescue => e; Y end").jump(:rescue)
      expect(ast.source).to eq "rescue => e; Y end"

      ast = stmt("begin; X; rescue A => e; Y end").jump(:rescue)
      expect(ast.source).to eq "rescue A => e; Y end"

      ast = stmt("begin; X; rescue A, B => e; Y end").jump(:rescue)
      expect(ast.source).to eq "rescue A, B => e; Y end"
    end

    it "handles method rescue blocks" do
      ast = stmt("def x; A; rescue Y; B end")
      expect(ast.source).to eq "def x; A; rescue Y; B end"
      expect(ast.jump(:rescue).source).to eq "rescue Y; B end"
    end

    it "handles defs with keywords as method name" do
      ast = stmt("# docstring\nclass A;\ndef class; end\nend")
      expect(ast.jump(:class).docstring).to eq "docstring"
      expect(ast.jump(:class).line_range).to eq(2..4)
    end

    it "handles defs with unnamed argument with default values" do
      ast = stmt('def hello(one, two = 2, three = 3) end').jump(:params)
      expect(ast.source).to eq 'one, two = 2, three = 3'
    end

    it "handles defs with splats" do
      ast = stmt('def hello(one, *two) end').jump(:params)
      expect(ast.source).to eq 'one, *two'
    end

    if YARD.ruby2?
      it "handles defs with named arguments with default values" do
        ast = stmt('def hello(one, two: 2, three: 3) end').jump(:params)
        expect(ast.source).to eq 'one, two: 2, three: 3'
      end
    end

    if NAMED_OPTIONAL_ARGUMENTS
      it "handles defs with named arguments without default values" do
        ast = stmt('def hello(one, two:, three:) end').jump(:params)
        expect(ast.source).to eq 'one, two:, three:'
      end

      it "handles defs with double splats" do
        ast = stmt('def hello(one, **two) end').jump(:params)
        expect(ast.source).to eq 'one, **two'
      end
    end

    it "ends source properly on array reference" do
      ast = stmt("AS[0, 1 ]   ")
      expect(ast.source).to eq 'AS[0, 1 ]'

      ast = stmt('def x(a = S[1]) end').jump(:params)
      expect(ast.source).to eq 'a = S[1]'
    end

    it "ends source properly on if/unless mod" do
      %w(if unless while).each do |mod|
        expect(stmt("A=1 #{mod} true").source).to eq "A=1 #{mod} true"
      end
    end

    it "shows proper source for assignment" do
      expect(stmt("A=1").jump(:assign).source).to eq "A=1"
    end

    it "shows proper source for a top_const_ref" do
      s = stmt("::\nFoo::Bar")
      expect(s.jump(:top_const_ref).source).to eq "::\nFoo"
      expect(s).to be_ref
      expect(s.jump(:top_const_ref)).to be_ref
      expect(s.source).to eq "::\nFoo::Bar"
      expect(s.line_range.to_a).to eq [1, 2]
    end

    it "shows proper source for inline heredoc" do
      src = "def foo\n  foo(<<-XML, 1, 2)\n    bar\n\n  XML\nend"
      s = stmt(src)
      t = tokenize(src)
      expect(s.source).to eq src
      expect(t.map {|x| x[1] }.join).to eq src
    end

    it "shows proper source for regular heredoc" do
      src = "def foo\n  x = <<-XML\n  Hello \#{name}!\n  Bye!\n  XML\nend"
      s = stmt(src)
      t = tokenize(src)
      expect(s.source).to eq src
      expect(t.map {|x| x[1] }.join).to eq src
    end

    it "shows proper source for heredoc with comment" do
      src = "def foo\n  x = <<-XML # HI!\n  Hello \#{name}!\n  Bye!\n  XML\nend"
      s = stmt(src)
      t = tokenize(src)
      expect(s.source).to eq src
      expect(t.map {|x| x[1] }.join).to eq src
    end

    it "shows proper source for string" do
      ["'", '"'].each do |q|
        src = "#{q}hello\n\nworld#{q}"
        s = stmt(src)
        expect(s.jump(:string_content).source).to eq "hello\n\nworld"
        expect(s.source).to eq src
      end

      src = '("this is a string")'
      expect(stmt(src).jump(:string_literal).source).to eq '"this is a string"'
    end

    %w(w W i I).each do |tok|
      it "shows proper source for %#{tok}() array" do
        src = "%#{tok}(\na b c\n d e f\n)"
        expect(stmt(src).source).to eq src
      end

      it "shows proper source for %#{tok}{} array" do
        src = "%#{tok}{\na b c\n d e f\n}"
        expect(stmt(src).source).to eq src
      end
    end

    {'i' => :qsymbols_literal, 'I' => :symbols_literal,
     'w' => :qwords_literal, 'W' => :words_literal}.each do |id, sym|
      it "parses %#{id}(...) literals" do
        [
          "TEST = %#{id}(A B C)",
          "TEST = %#{id}(  A  B  C  )",
          "TEST = %#{id}( \nA \nB \nC \n)",
          "TEST = %#{id}(\n\nAD\n\nB\n\nC\n\n)",
          "TEST = %#{id}(\n A\n B\n C\n )"
        ].each do |str|
          node = stmt(str).jump(sym)
          expect(node.source).to eq(str[/(\%#{id}\(.+\))/m, 1])
        end
      end

      it "tokenizing %#{id}(...) returns correct tokens" do
        toks = tokenize("TEST = %#{id}(A B C)").flatten
        expect(toks.count(:tstring_content)).to eq(3)
      end
    end

    it "properly tokenizes symbols" do
      tokens = tokenize(<<-eof)
        class X
          Foo = :''
          Fuu = :bar
          Bar = :BAR
          Baz = :"B+z"
          Qux = :if
        end
      eof
      symbols = tokens.select {|t| t[0] == :symbol }.map {|t| t[1] }
      expect(symbols).to eq %w(:'' :bar :BAR :"B+z" :if)
    end

    it "parses %w() array in constant declaration" do
      s = stmt(<<-eof)
        class Foo
          FOO = %w( foo bar )
        end
      eof
      expect(s.jump(:qwords_literal).source).to eq '%w( foo bar )'
      if RUBY_VERSION >= '1.9.3' # ripper fix: array node encapsulates qwords
        expect(s.jump(:array).source).to eq '%w( foo bar )'
      end
    end

    it "parses %w() array source in object[] parsed context" do
      s = stmts(<<-eof)
        {}[:key]
        FOO = %w( foo bar )
      eof
      expect(s[1].jump(:array).source).to eq '%w( foo bar )'
    end

    it "parses %w() array source in object[]= parsed context" do
      s = stmts(<<-eof)
        {}[:key] = :value
        FOO = %w( foo bar )
      eof
      expect(s[1].jump(:array).source).to eq '%w( foo bar )'
    end

    it "parses [] as array" do
      s = stmt(<<-eof)
        class Foo
          FOO = ['foo', 'bar']
        end
      eof
      expect(s.jump(:array).source).to eq "['foo', 'bar']"
    end

    it "shows source for unary minus" do
      expect(stmt("X = - 1").jump(:unary).source).to eq '- 1'
    end

    it "shows source for unary exclamation" do
      expect(stmt("X = !1").jump(:unary).source).to eq '!1'
    end

    it "has the correct line range for class/modules" do
      s = stmt(<<-eof)
        class Foo
          def foo; end



          # Ending comment
        end
      eof
      expect(s.jump(:class).line_range).to eq(1..7)
    end

    it "has the correct line range for blocks" do
      Registry.clear
      ast = YARD.parse_string(<<-eof).enumerator
        module A
          some_method
        end
      eof
      expect(ast.first.block.source.strip).to eq "some_method"
    end

    it "finds lone comments" do
      Registry.clear
      ast = YARD.parse_string(<<-eof).enumerator
        class Foo
          ##
          # comment here


          def foo; end

          # end comment
        end
      eof
      comment = ast.first.last.jump(:comment)
      expect(comment.type).to eq :comment
      expect(comment.docstring_hash_flag).to be true
      expect(comment.docstring.strip).to eq "comment here"

      expect(ast.first.last.last.type).to eq :comment
      expect(ast.first.last.last.docstring).to eq "end comment"
    end

    it "does not group comments if they don't begin the line" do
      Registry.clear
      YARD.parse_string(<<-eof).enumerator
        class Foo
          CONST1 = 1 # Comment here
          CONST2 = 2 # Another comment here
        end
      eof
      expect(Registry.at("Foo::CONST1").docstring).to eq "Comment here"
      expect(Registry.at("Foo::CONST2").docstring).to eq "Another comment here"
    end

    it "handles comments in the middle of a multi-line statement" do
      Registry.clear
      YARD.parse_string <<-eof
        foo # BREAK
        .bar

        # Documentation
        class Baz; end
      eof
      expect(Registry.at('Baz')).not_to be_nil
      expect(Registry.at('Baz').docstring).to eq 'Documentation'
    end

    %w(if unless).each do |type|
      it "does not get confused by modifier '#{type}' statements" do
        Registry.clear
        YARD.parse_string(<<-eof).enumerator
          module Foo
            #{type} test?
              # Docstring
              class Bar
                # Docstring2
                def foo
                  x #{type} true
                end
              end
            end
          end
        eof

        expect(Registry.at("Foo::Bar").docstring).to eq "Docstring"
        expect(Registry.at("Foo::Bar#foo").docstring).to eq "Docstring2"
      end

      it "supports #{type} statements at start of source" do
        Registry.clear
        YARD.parse_string <<-eof
          #{type} condition?
            class Foo; def bar; #{type} true; end end end
          end
        eof

        expect(log.io.string).to eq ""
        expect(Registry.at('Foo#bar')).not_to eq nil
      end

      it "can handle complex non-modifier '#{type}' statements" do
        Registry.clear
        YARD.parse_string <<-eof
          class Foo
            def initialize(data, options = Hash.new)
              #{type} true; raise "error" end
              @x = ( #{type} 1; true end ) # This line should not blow up
            end
          end
        eof

        expect(log.io.string).to eq ""
        expect(Registry.at('Foo#initialize')).not_to eq nil
      end

      it "does not add comment blocks to #{type}_mod nodes" do
        Registry.clear
        YARD.parse_string(<<-eof).enumerator
          class Foo
            # Docstring
            def bar; end if true
          end
        eof

        expect(Registry.at("Foo#bar").docstring).to eq "Docstring"
      end
    end

    it "removes frozen string line from initial file comments" do
      YARD.parse_string "# frozen_string_literal: true\n# this is a comment\nclass Foo; end"
      YARD.parse_string "# Frozen-string-literal: true\n# this is a comment\nclass Bar; end"

      expect(Registry.at(:Foo).docstring).to eq "this is a comment"
      expect(Registry.at(:Bar).docstring).to eq "this is a comment"
    end

    it "handles compile errors" do
      expect { stmt(":~$ Do not clobber") }.to raise_error(Parser::ParserSyntaxError)
    end
  end
end if HAVE_RIPPER
