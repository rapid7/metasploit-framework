# frozen_string_literal: true
begin require 'ripper'; rescue LoadError; nil end

module YARD
  module Parser
    module Ruby
      # Ruby 1.9 parser
      # @!attribute [r] encoding_line
      # @!attribute [r] frozen_string_line
      # @!attribute [r] shebang_line
      # @!attribute [r] enumerator
      class RubyParser < Parser::Base
        def initialize(source, filename)
          @parser = RipperParser.new(source, filename)
        end

        def parse; @parser.parse end
        def tokenize; @parser.tokens end
        def enumerator; @parser.enumerator end
        def shebang_line; @parser.shebang_line end
        def encoding_line; @parser.encoding_line end
        def frozen_string_line; @parser.frozen_string_line end
      end

      # Internal parser class
      # @since 0.5.6
      class RipperParser < Ripper
        attr_reader :ast, :charno, :comments, :file, :tokens
        attr_reader :shebang_line, :encoding_line, :frozen_string_line
        alias root ast

        def initialize(source, filename, *args)
          super
          @last_ns_token = nil
          @file = filename
          @source = source
          @tokens = []
          @comments = {}
          @comments_range = {}
          @comments_flags = {}
          @heredoc_tokens = nil
          @heredoc_state = nil
          @map = {}
          @ns_charno = 0
          @list = []
          @charno = 0
          @shebang_line = nil
          @encoding_line = nil
          @frozen_string_line = nil
          @file_encoding = nil
          @newline = true
          @percent_ary = nil
        end

        def parse
          @ast = super
          @ast.full_source = @source
          @ast.file = @file
          freeze_tree
          insert_comments
          self
        end

        def enumerator
          ast.children
        end

        def file_encoding
          return nil unless defined?(::Encoding)
          return @file_encoding if @file_encoding
          return Encoding.default_internal unless @encoding_line
          match = @encoding_line.match(SourceParser::ENCODING_LINE)
          @file_encoding = match.captures.last if match
        end

        private

        MAPPINGS = {
          :BEGIN => "BEGIN",
          :END => "END",
          :alias => "alias",
          :array => :lbracket,
          :arg_paren => :lparen,
          :begin => "begin",
          :blockarg => "&",
          :brace_block => :lbrace,
          :break => "break",
          :case => "case",
          :class => "class",
          :def => "def",
          :defined => "defined?",
          :defs => "def",
          :do_block => "do",
          :else => "else",
          :elsif => "elsif",
          :ensure => "ensure",
          :for => "for",
          :hash => :lbrace,
          :if => "if",
          :lambda => [:tlambda, "lambda"],
          :module => "module",
          :next => "next",
          :paren => :lparen,
          :qwords_literal => :qwords_beg,
          :words_literal => :words_beg,
          :qsymbols_literal => :qsymbols_beg,
          :symbols_literal => :symbols_beg,
          :redo => "redo",
          :regexp_literal => :regexp_beg,
          :rescue => "rescue",
          :rest_param => "*",
          :retry => "retry",
          :return => "return",
          :return0 => "return",
          :sclass => "class",
          :string_embexpr => :embexpr_beg,
          :string_literal => [:tstring_beg, :heredoc_beg],
          :super => "super",
          :symbol => :symbeg,
          :top_const_ref => "::",
          :undef => "undef",
          :unless => "unless",
          :until => "until",
          :when => "when",
          :while => "while",
          :xstring_literal => :backtick,
          :yield => "yield",
          :yield0 => "yield",
          :zsuper => "super"
        }
        REV_MAPPINGS = {}

        AST_TOKENS = [:CHAR, :backref, :const, :cvar, :gvar, :heredoc_end, :ident,
          :int, :float, :ivar, :label, :period, :regexp_end, :tstring_content, :backtick]

        MAPPINGS.each do |k, v|
          if Array === v
            v.each {|vv| (REV_MAPPINGS[vv] ||= []) << k }
          else
            (REV_MAPPINGS[v] ||= []) << k
          end
        end

        PARSER_EVENT_TABLE.each do |event, arity|
          node_class = AstNode.node_class_for(event)

          if /_new\z/ =~ event.to_s && arity == 0
            module_eval(<<-eof, __FILE__, __LINE__ + 1)
              def on_#{event}(*args)
                #{node_class}.new(:list, args, :listchar => charno...charno, :listline => lineno..lineno)
              end
            eof
          elsif /_add(_.+)?\z/ =~ event.to_s
            module_eval(<<-eof, __FILE__, __LINE__ + 1)
              begin; undef on_#{event}; rescue NameError; end
              def on_#{event}(list, item)
                list.push(item)
                list
              end
            eof
          elsif MAPPINGS.key?(event)
            module_eval(<<-eof, __FILE__, __LINE__ + 1)
              begin; undef on_#{event}; rescue NameError; end
              def on_#{event}(*args)
                visit_event #{node_class}.new(:#{event}, args)
              end
            eof
          else
            module_eval(<<-eof, __FILE__, __LINE__ + 1)
              begin; undef on_#{event}; rescue NameError; end
              def on_#{event}(*args)
                #{node_class}.new(:#{event}, args, :listline => lineno..lineno, :listchar => charno...charno)
              end
            eof
          end
        end

        SCANNER_EVENTS.each do |event|
          ast_token = AST_TOKENS.include?(event)
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{event}; rescue NameError; end
            def on_#{event}(tok)
              visit_ns_token(:#{event}, tok, #{ast_token.inspect})
            end
          eof
        end

        REV_MAPPINGS.select {|k, _v| k.is_a?(Symbol) }.each do |pair|
          event = pair.first
          ast_token = AST_TOKENS.include?(event)
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{event}; rescue NameError; end
            def on_#{event}(tok)
              (@map[:#{event}] ||= []) << [lineno, charno]
              visit_ns_token(:#{event}, tok, #{ast_token.inspect})
            end
          eof
        end

        [:kw, :op].each do |event|
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{event}; rescue NameError; end
            def on_#{event}(tok)
              unless @last_ns_token == [:kw, "def"] ||
                  (@tokens.last && @tokens.last[0] == :symbeg) ||
                  (!@newline && %w(if while until unless).include?(tok))
                (@map[tok] ||= []) << [lineno, charno]
              end
              visit_ns_token(:#{event}, tok, true)
            end
          eof
        end

        [:nl, :ignored_nl].each do |event|
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{event}; rescue NameError; end
            def on_#{event}(tok)
              add_token(:#{event}, tok)
              @newline = true
              @charno += tok ? tok.length : 0
            end
          eof
        end

        undef on_sp

        def on_sp(tok)
          add_token(:sp, tok)
          @charno += tok.length
        end

        def visit_event(node)
          map = @map[MAPPINGS[node.type]]
          lstart, sstart = *(map ? map.pop : [lineno, @ns_charno - 1])
          node.source_range = Range.new(sstart, @ns_charno - 1)
          node.line_range = Range.new(lstart, lineno)
          if node.respond_to?(:block)
            sr = node.block.source_range
            lr = node.block.line_range
            node.block.source_range = Range.new(sr.first, @tokens.last[2][1] - 1)
            node.block.line_range = Range.new(lr.first, @tokens.last[2][0])
          end
          node
        end

        def visit_event_arr(node)
          mapping = MAPPINGS[node.type].find {|k| @map[k] && !@map[k].empty? }
          lstart, sstart = *@map[mapping].pop
          node.source_range = Range.new(sstart, @ns_charno - 1)
          node.line_range = Range.new(lstart, lineno)
          node
        end

        def visit_ns_token(token, data, ast_token = false)
          add_token(token, data)
          ch = charno
          @last_ns_token = [token, data]
          @charno += data.length
          @ns_charno = charno
          @newline = [:semicolon, :comment, :kw, :op, :lparen, :lbrace].include?(token)
          if ast_token
            AstNode.new(token, [data], :line => lineno..lineno, :char => ch..charno - 1, :token => true)
          end
        end

        def add_token(token, data)
          if @percent_ary
            if token == :words_sep && data !~ /\s\z/
              rng = @percent_ary.source_range
              rng = Range.new(rng.first, rng.last + data.length)
              @percent_ary.source_range = rng
              @tokens << [token, data, [lineno, charno]]
              @percent_ary = nil
              return
            elsif token == :tstring_end && data =~ /\A\s/
              rng = @percent_ary.source_range
              rng = Range.new(rng.first, rng.last + data.length)
              @percent_ary.source_range = rng
              @tokens << [token, data, [lineno, charno]]
              @percent_ary = nil
              return
            end
          end

          if @tokens.last && (@tokens.last[0] == :symbeg ||
              (@tokens.last[0] == :symbol && token.to_s =~ /^tstring/))
            @tokens[-1] = [:symbol, @tokens.last[1] + data, @tokens.last[2]]
          elsif @heredoc_state == :started
            @heredoc_tokens << [token, data, [lineno, charno]]

            # fix ripper encoding of heredoc bug
            # (see http://bugs.ruby-lang.org/issues/6200)
            data.force_encoding(file_encoding) if file_encoding

            @heredoc_state = :ended if token == :heredoc_end
          elsif (token == :nl || token == :comment) && @heredoc_state == :ended
            @heredoc_tokens.unshift([token, data, [lineno, charno]])
            @tokens += @heredoc_tokens
            @heredoc_tokens = nil
            @heredoc_state = nil
          else
            @tokens << [token, data, [lineno, charno]]
            if token == :heredoc_beg
              @heredoc_state = :started
              @heredoc_tokens = []
            end
          end
        end

        undef on_program
        undef on_assoc_new
        undef on_array
        undef on_hash
        undef on_bare_assoc_hash
        undef on_assoclist_from_args
        undef on_aref
        undef on_aref_field
        undef on_lbracket
        undef on_rbracket
        undef on_string_literal
        undef on_lambda
        undef on_unary
        undef on_string_content
        undef on_rescue
        undef on_void_stmt
        undef on_params
        undef on_label
        undef on_comment
        undef on_embdoc_beg
        undef on_embdoc
        undef on_embdoc_end
        undef on_parse_error
        undef on_bodystmt
        undef on_top_const_ref
        undef on_const_path_ref

        def on_program(*args)
          args.first
        end

        def on_body_stmt(*args)
          args.compact.size == 1 ? args.first : AstNode.new(:list, args)
        end
        alias on_bodystmt on_body_stmt

        def on_assoc_new(*args)
          AstNode.new(:assoc, args)
        end

        def on_hash(*args)
          visit_event AstNode.new(:hash, args.first || [])
        end

        def on_bare_assoc_hash(*args)
          AstNode.new(:list, args.first)
        end

        def on_assoclist_from_args(*args)
          args.first
        end

        def on_unary(op, val)
          map = @map[op.to_s[0, 1]]
          lstart, sstart = *(map ? map.pop : [lineno, @ns_charno - 1])
          node = AstNode.node_class_for(:unary).new(:unary, [op, val])
          node.source_range = Range.new(sstart, @ns_charno - 1)
          node.line_range = Range.new(lstart, lineno)
          node
        end

        def on_aref(*args)
          @map[:lbracket].pop
          ll, lc = *@map[:aref].pop
          sr = args.first.source_range.first..lc
          lr = args.first.line_range.first..ll
          AstNode.new(:aref, args, :char => sr, :line => lr)
        end

        def on_aref_field(*args)
          @map[:lbracket].pop
          AstNode.new(:aref_field, args,
                      :listline => lineno..lineno, :listchar => charno...charno)
        end

        def on_array(other)
          node = AstNode.node_class_for(:array).new(:array, [other])
          map = @map[MAPPINGS[node.type]]
          if map && !map.empty?
            lstart, sstart = *map.pop
            node.source_range = Range.new(sstart, @ns_charno - 1)
            node.line_range = Range.new(lstart, lineno)
          else
            sstart = other.source_range.begin
            lstart = other.line_range.begin
            node.source_range = Range.new(sstart, @ns_charno - 1)
            node.line_range = Range.new(lstart, lineno)
            node.source_range = other.source_range
            node.line_range = other.line_range
          end
          node
        end

        def on_lbracket(tok)
          (@map[:lbracket] ||= []) << [lineno, charno]
          visit_ns_token(:lbracket, tok, false)
        end

        def on_rbracket(tok)
          (@map[:aref] ||= []) << [lineno, charno]
          visit_ns_token(:rbracket, tok, false)
        end

        def on_top_const_ref(*args)
          type = :top_const_ref
          node = AstNode.node_class_for(type).new(type, args)
          mapping = @map[MAPPINGS[type]]
          extra_op = mapping.last[1] + 2 == charno ? mapping.pop : nil
          lstart, sstart = *mapping.pop
          node.source_range = Range.new(sstart, args.last.source_range.last)
          node.line_range = Range.new(lstart, args.last.line_range.last)
          mapping.push(extra_op) if extra_op
          node
        end

        def on_const_path_ref(*args)
          ReferenceNode.new(:const_path_ref, args, :listline => lineno..lineno, :listchar => charno..charno)
        end

        [:if_mod, :unless_mod, :while_mod, :until_mod].each do |kw|
          node_class = AstNode.node_class_for(kw)
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{kw}; rescue NameError; end
            def on_#{kw}(*args)
              sr = args.last.source_range.first..args.first.source_range.last
              lr = args.last.line_range.first..args.first.line_range.last
              #{node_class}.new(:#{kw}, args, :line => lr, :char => sr)
            end
          eof
        end

        %w(symbols qsymbols words qwords).each do |kw|
          module_eval(<<-eof, __FILE__, __LINE__ + 1)
            begin; undef on_#{kw}_new; rescue NameError; end
            def on_#{kw}_new(*args)
              node = LiteralNode.new(:#{kw}_literal, args)
              @percent_ary = node
              if @map[:#{kw}_beg]
                lstart, sstart = *@map[:#{kw}_beg].pop
                node.source_range = Range.new(sstart, @ns_charno-1)
                node.line_range = Range.new(lstart, lineno)
              end
              node
            end

            begin; undef on_#{kw}_add; rescue NameError; end
            def on_#{kw}_add(list, item)
              last = @source[@ns_charno,1] == "\n" ? @ns_charno - 1 : @ns_charno
              list.source_range = (list.source_range.first..last)
              list.line_range = (list.line_range.first..lineno)
              list.push(item)
              list
            end
          eof
        end

        def on_string_literal(*args)
          node = visit_event_arr(LiteralNode.new(:string_literal, args))
          if args.size == 1
            r = args[0].source_range
            if node.source_range != Range.new(r.first - 1, r.last + 1)
              klass = AstNode.node_class_for(node[0].type)
              r = Range.new(node.source_range.first + 1, node.source_range.last - 1)
              node[0] = klass.new(node[0].type, [@source[r]], :line => node.line_range, :char => r)
            end
          end
          node
        end

        def on_lambda(*args)
          visit_event_arr AstNode.new(:lambda, args)
        end

        def on_string_content(*args)
          AstNode.new(:string_content, args, :listline => lineno..lineno, :listchar => charno..charno)
        end

        def on_rescue(exc, *args)
          exc = AstNode.new(:list, exc) if exc
          visit_event AstNode.new(:rescue, [exc, *args])
        end

        def on_void_stmt
          AstNode.new(:void_stmt, [], :line => lineno..lineno, :char => charno...charno)
        end

        def on_params(*args)
          args.map! do |arg|
            next arg unless arg.class == Array

            if arg.first.class == Array
              arg.map! do |sub_arg|
                next sub_arg unless sub_arg.class == Array
                type = sub_arg[0].type == :label ?
                  :named_arg : :unnamed_optional_arg
                AstNode.new(type, sub_arg, :listline => lineno..lineno, :listchar => charno..charno)
              end
            end

            AstNode.new(:list, arg, :listline => lineno..lineno, :listchar => charno..charno)
          end

          ParameterNode.new(:params, args, :listline => lineno..lineno, :listchar => charno..charno)
        end

        def on_label(data)
          add_token(:label, data)
          ch = charno
          @charno += data.length
          @ns_charno = charno
          AstNode.new(:label, [data[0...-1]], :line => lineno..lineno, :char => ch..charno - 1, :token => true)
        end

        def on_comment(comment)
          not_comment = false
          if @last_ns_token.nil? || @last_ns_token.empty?
            if comment =~ SourceParser::SHEBANG_LINE && !@encoding_line
              @shebang_line = comment
              not_comment = true
            elsif comment =~ SourceParser::ENCODING_LINE
              @encoding_line = comment
              not_comment = true
            elsif comment =~ SourceParser::FROZEN_STRING_LINE
              @frozen_string_line = comment
              not_comment = true
            end
          end

          ch = charno
          visit_ns_token(:comment, comment)
          if not_comment
            @last_ns_token = nil
            return
          end

          source_range = ch..(charno - 1)
          comment = comment.gsub(/^(\#+)\s{0,1}/, '').chomp
          append_comment = @comments[lineno - 1]

          hash_flag = $1 == '##' ? true : false

          if append_comment && @comments_last_column &&
             @comments_last_column == column && comment_starts_line?(ch)
            @comments.delete(lineno - 1)
            @comments_flags[lineno] = @comments_flags[lineno - 1]
            @comments_flags.delete(lineno - 1)
            range = @comments_range.delete(lineno - 1)
            source_range = range.first..source_range.last
            comment = append_comment + "\n" + comment
          end

          @comments[lineno] = comment
          @comments_range[lineno] = source_range
          @comments_flags[lineno] = hash_flag unless append_comment
          @comments_last_column = column
        end

        def on_embdoc_beg(text)
          visit_ns_token(:embdoc_beg, text)
          @embdoc_start = charno - text.length
          @embdoc = String.new("")
        end

        def on_embdoc(text)
          visit_ns_token(:embdoc, text)
          @embdoc << text
        end

        def on_embdoc_end(text)
          visit_ns_token(:embdoc_end, text)
          @comments_last_column = nil
          @comments[lineno] = @embdoc
          @comments_range[lineno] = @embdoc_start...charno
          @embdoc_start = nil
          @embdoc = nil
        end

        def on_parse_error(msg)
          raise ParserSyntaxError, "syntax error in `#{file}`:(#{lineno},#{column}): #{msg}"
        end
        alias compile_error on_parse_error

        def comment_starts_line?(charno)
          (charno - 1).downto(0) do |i|
            ch = @source[i]
            break if ch == "\n"
            return false if ch != " " && ch != "\t"
          end
          true
        end

        def insert_comments
          root.traverse do |node|
            next if node.type == :comment || node.type == :list || node.parent.type != :list

            # never attach comments to if/unless mod nodes
            if node.type == :if_mod || node.type == :unless_mod
              node = node.then_block
            end

            # check upwards from line before node; check node's line at the end
            ((node.line - 1).downto(node.line - 2).to_a + [node.line]).each do |line|
              comment = @comments[line]
              if comment && !comment.empty?
                add_comment(line, node)
                break
              end
            end

            @comments.keys.each do |line|
              add_comment(line, nil, node) if node.line > line
            end
          end

          # insert any lone unadded comments before node
          root.traverse do |node|
            next if node.type == :list || node.parent.type != :list
            @comments.keys.each do |line|
              next unless node.line_range.include?(line)
              pick = nil
              node.traverse do |subnode|
                next unless subnode.type == :list
                pick ||= subnode
                next unless subnode.line_range.include?(line)
                pick = subnode
              end
              add_comment(line, nil, pick, true) if pick
            end
          end unless @comments.empty?

          # insert all remaining comments
          @comments.each do |line, _comment|
            add_comment(line, nil, root, true)
          end

          @comments = {}
        end

        def add_comment(line, node = nil, before_node = nil, into = false)
          comment = @comments[line]
          source_range = @comments_range[line]
          line_range = ((line - comment.count("\n"))..line)
          if node.nil?
            node = CommentNode.new(:comment, [comment], :line => line_range, :char => source_range)
            if into
              before_node.push(node)
              before_node.unfreeze
              node.parent = before_node
            elsif before_node
              parent_node = before_node.parent
              idx = parent_node.index(before_node)
              parent_node.insert(idx, node)
              parent_node.unfreeze
              node.parent = parent_node
            end
          end
          node.docstring = comment
          node.docstring_hash_flag = @comments_flags[line]
          node.docstring_range = line_range
          @comments.delete(line)
          @comments_range.delete(line)
          @comments_flags.delete(line)
        end

        def freeze_tree(node = nil)
          nodes = [node || root]
          until nodes.empty?
            p_node = nodes.shift
            p_node.children.each do |child|
              child.parent = p_node
              nodes << child
            end
          end
        end
      end if defined?(::Ripper)
    end
  end
end
