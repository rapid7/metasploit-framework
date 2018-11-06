# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::DecoratorHandlerMethods" do
  describe "#process_decorator" do
    # Create a YARD decorator handler.
    # @param name [Symbol] name of the mock decorator
    def create_test_handler(name)
      data[name] = {}

      local_mock_handler_opts = mock_handler_opts
      local_nodes = nodes
      local_data = data[name]

      Class.new YARD::Handlers::Ruby::Base do
        include YARD::Handlers::Ruby::DecoratorHandlerMethods

        handles method_call(:"#{name}_decorator")
        namespace_only

        process do
          # process_decorator params written like this due to Ruby 1.8.
          # A modern handler should splat local_nodes.
          local_data[:return] =
            process_decorator(*(local_nodes + [local_mock_handler_opts])) do |method, node, mname|
              local_data[:method] = method
              local_data[:node] = node
              local_data[:name] = mname
            end
        end
      end
    end

    # Generate method definition.
    # @param symbols [Symbol] method names
    # @return [String] method definition code
    def make_defs(*symbols)
      symbols.map do |s|
        s = "self.#{s}" if mock_handler_opts[:scope] == :class
        "def #{s}; end"
      end.join("\n")
    end

    # Generate an AST for the given source code string.
    def make_ast(code)
      YARD::Parser::Ruby::RubyParser.new(code, nil).parse.ast
    end

    subject { data[:mock] }

    let(:data) { Hash.new }
    let(:nodes) { [] }
    let(:mock_handler_opts) { {:scope => :instance} }
    let(:class_name)    { 'DecoratorTest' }
    let(:docstring)     { 'the foo method' }
    let(:param_string)  { 'def foo param1, param2; end' }
    let(:method_defs)   { [] }
    let(:method_string) { "#{class_name}#foo" }
    let(:code) do
      <<-eof
      class #{class_name}
        #{make_defs(*method_defs)}
        # #{docstring}
        mock_decorator #{param_string}
      end
      eof
    end

    before do
      Registry.clear
      YARD::Handlers::Base.clear_subclasses

      create_test_handler :mock
      create_test_handler :first
      create_test_handler :second
      create_test_handler :third

      StubbedSourceParser.parse_string code
    end

    it "returns an array of hashes containing the method proxy, node, and name" do
      expect(subject[:return]).to be_an Array
      expect(subject[:return].first[:name].to_s).to eq 'foo'
      expect(subject[:return].first[:method].to_s).to eq method_string
      expect(subject[:return].first[:node]).to be_a YARD::Parser::Ruby::AstNode
    end

    describe "method is a MethodObject if the method has been defined" do
      let(:code) { "class DecoratorTest; mock_decorator def foo; end; end" }

      specify do
        expect(subject[:return].first[:method]).
          to be_a YARD::CodeObjects::MethodObject
      end
    end

    describe "method is a Proxy if the method has not been defined" do
      let(:code) { "class DecoratorTest; mock_decorator :foo; end" }

      specify do
        expect(subject[:return].first[:method]).to be_a YARD::CodeObjects::Proxy
      end
    end

    specify "block yields method proxy, node, name" do
      expect(subject[:name]).to be_a Symbol
      expect(subject[:name]).to eq :foo

      expect(subject[:method]).to be_a YARD::CodeObjects::MethodObject
      expect(subject[:method].to_s).to eq method_string

      expect(subject[:node]).to be_a YARD::Parser::Ruby::AstNode
    end

    describe "capitalized method names" do
      let(:method_defs)   { [:Foo] }
      let(:param_string)  { 'def Foo param1, param2; end' }

      specify do
        expect(subject[:method].to_s).to eq "#{class_name}#Foo"
      end
    end

    describe "nodes argument" do
      subject { data[:mock][:return].map {|h| h[:method].to_s } }

      describe "assumes all params refer to methods by default" do
        let(:method_defs)  { [:foo, :bar] }
        let(:param_string) { method_defs.map(&:inspect).join(',') }
        let(:nodes) { [] }

        specify do
          expect(subject).to eq ["#{class_name}#foo", "#{class_name}#bar"]
        end
      end

      describe "can specify which params to capture as methods" do
        let(:method_defs) { [:foo, :bar, :baz, :bat] }
        let(:parameters) do
          [:option_1, :baz, :bat, :option_2, :foo, :bar].map do |s|
            make_ast s.inspect
          end
        end

        describe "as a single param" do
          let(:nodes) { parameters[4] }

          specify do
            expect(subject).to eq ["#{class_name}#foo"]
          end
        end

        describe "as a list of params" do
          let(:nodes) { [parameters[4], parameters[5]] }

          specify do
            expect(subject).to eq ["#{class_name}#foo", "#{class_name}#bar"]
          end
        end

        describe "as a range" do
          let(:nodes) { parameters[4..-1] }

          specify do
            expect(subject).to eq ["#{class_name}#foo", "#{class_name}#bar"]
          end
        end

        describe "as multiple ranges" do
          # Written like this due to Ruby 1.8. Can also splat the ranges as
          # separate params:
          #   *parameters[1..2], *parameters[4..-1]
          let(:nodes) { parameters[1..2] + parameters[4..-1] }

          specify do
            expect(subject).to eq [
              "#{class_name}#baz",
              "#{class_name}#bat",
              "#{class_name}#foo",
              "#{class_name}#bar"
            ]
          end
        end
      end

      describe "can select no nodes by passing nil" do
        let(:nodes) { [nil] }

        specify do
          expect(subject).to eq []
        end
      end
    end

    describe "scope option" do
      describe "defaults to :instance" do
        let(:mock_handler_opts) { {} }

        specify do
          expect(subject[:return].first[:method].to_s).to eq method_string
        end
      end

      describe "creates method proxies" do
        shared_examples "decorator helper scope" do
          let(:param_string) { decorator_params.map(&:inspect).join(',') }

          describe "for symbols" do
            let(:decorator_params) { [:foo, :bar] }

            specify do
              expect(subject.count).to eq decorator_params.count

              subject.each_with_index do |_, i|
                expect(subject[i]).to be_a YARD::CodeObjects::MethodObject
                expect(subject[i].to_s).to eq \
                  "#{class_name}#{mock_handler_opts[:scope] == :class ? '.' : '#'}#{decorator_params[i]}"
              end
            end
          end

          describe "for string literals" do
            let(:decorator_params) { ['foo', 'bar'] }

            specify do
              expect(subject.count).to eq decorator_params.count

              subject.each_with_index do |_, i|
                expect(subject[i]).to be_a YARD::CodeObjects::MethodObject
                expect(subject[i].to_s).to eq \
                  "#{class_name}#{mock_handler_opts[:scope] == :class ? '.' : '#'}#{decorator_params[i]}"
              end
            end
          end

          describe "for methods" do
            let(:param_string) { decorator_params.join(',') }
            let(:decorator_params) do
              ["def #{'self.' if mock_handler_opts[:scope] == :class}foo f1, f2; end",
              "def #{'self.' if mock_handler_opts[:scope] == :class}bar b1, b2; end"]
            end

            specify do
              expect(subject.count).to eq decorator_params.count

              subject.each_with_index do |_, i|
                expect(subject[i]).to be_a YARD::CodeObjects::MethodObject
                expect(subject[i].to_s).to eq \
                  class_name +
                  (mock_handler_opts[:scope] == :class ? '.' : '#') +
                  decorator_params[i].split(' ')[1][/\w+$/]
              end
            end
          end
        end # decorator helper scope shared examples

        subject { data[:mock][:return].map {|h| h[:method] } }

        let(:docstring) { 'the foo method' }
        let(:method_defs) { [:foo, :bar] }

        describe "for :instance" do
          let(:mock_handler_opts) { {:scope => :instance} }

          include_examples "decorator helper scope"
        end

        describe "for :class" do
          let(:mock_handler_opts) { {:scope => :class} }

          include_examples "decorator helper scope"
        end
      end
    end

    describe "docstring from decorator" do
      subject { Registry.at method_string }

      specify "attaches to method definitions as decorator parameters" do
        expect(subject.docstring).to eq docstring
      end

      describe "does not attach" do
        describe "to undefined methods" do
          let(:code) do
            <<-eof
            class #{class_name}
              # #{docstring}
              mock_decorator :foo
            end
            eof
          end

          specify do
            expect(subject).not_to respond_to :docstring
          end
        end

        describe "to methods with existing docstring" do
          let(:code) do
            <<-eof
            class #{class_name}

              # original docstring
              def foo; end

              # #{docstring}
              mock_decorator :foo
            end
            eof
          end

          specify do
            expect(subject.docstring).to eq 'original docstring'
          end
        end
      end
    end

    describe "chained decorators" do
      subject { Registry.at method_string }

      let(:param_string) { 'def foo param1, param2; end' }
      let(:code) do
        <<-eof
        class #{class_name}
          #{make_defs(*method_defs)}
          # #{docstring}
          first_decorator second_decorator third_decorator #{param_string}
        end
        eof
      end

      specify "register nested method defs" do
        expect(subject).to be_a YARD::CodeObjects::MethodObject
      end

      describe "transfer docstring to decorated method defs" do
        specify do
          expect(subject.docstring).to eq docstring
        end

        describe "unless opt-out param is set" do
          let(:mock_handler_opts) { {:transfer_docstring => false} }

          specify do
            expect(subject.docstring.empty?).to be true
          end
        end
      end

      describe "don't transfer docstring to referenced methods" do
        let(:method_defs)  { [:foo] }
        let(:param_string) { ':foo' }

        specify do
          expect(subject.docstring.empty?).to be true
        end
      end

      specify "don't transfer docstring to other decorators" do
        expect(Registry.at("#{class_name}#second_decorator")).
          not_to respond_to :docstring

        expect(Registry.at("#{class_name}#third_decorator")).
          not_to respond_to :docstring
      end

      describe "transfer source to decorated method defs" do
        specify do
          expect(subject.source).to eq code.lines.to_a[-2].strip
        end

        describe "unless opt-out param is set" do
          let(:mock_handler_opts) { {:transfer_source => false} }

          specify do
            expect(subject.source).to eq param_string
          end
        end
      end

      describe "don't transfer source to referenced methods" do
        let(:method_defs)  { [:foo] }
        let(:param_string) { ':foo' }

        specify do
          expect(subject.source).to eq make_defs(*method_defs)
        end
      end
    end
  end # process_decorator
end unless LEGACY_PARSER
