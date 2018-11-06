# frozen_string_literal: true
RSpec.shared_examples "class method visibility decorator" do
  # Use let(:visibility) to specify the name of the x_class_method
  # visibility decorator to test.

  describe do
    before do
      StubbedSourceParser.parse_string <<-CODE
        class A
          def self.b; end
          def self.c; end
          def self.d; end
          def self.e; end

          #{visibility}_class_method(:c, :d)
          #{visibility}_class_method("e")
        end
      CODE
    end

    it "handles private_class_method statement" do
      expect(Registry.at('A.c').visibility).to eq visibility
      expect(Registry.at('A.d').visibility).to eq visibility
      expect(Registry.at('A.e').visibility).to eq visibility
    end

    # Issue #760
    # https://github.com/lsegal/yard/issues/760
    it "handles singleton classes" do
      # Note: It's important to def a method within the singleton class or
      #       the bug may not trigger.
      code = <<-CODE
        class SingletonClass
          private_class_method :new
          def self.foo
            "foo"
          end
        end
      CODE

      StubbedSourceParser.parse_string(code) # Should be successful.
    end unless LEGACY_PARSER
  end

  describe "handles reopened class" do
    before do
      StubbedSourceParser.parse_string <<-CODE
        class SingletonClass

          #{'private' unless visibility.to_sym == :private}

          # != visibility
          def self.foo
            'foo'
          end

          # == visibility
          def self.bar
          end

          # == visibility from reopening class.
          def self.baz
          end

          #{visibility}_class_method :new, :bar

        end
      CODE

      StubbedSourceParser.parse_string <<-CODE
        # Reopening singleton class.
        class SingletonClass
          #{visibility}_class_method :baz

          #{'private' unless visibility.to_sym == :private}
          # != visibility from reopened class. (Verifies class was reopened.)
          def self.bat
          end

        end
      CODE
    end

    specify do
      expect(Registry.at('SingletonClass.foo').visibility).not_to eq visibility
      expect(Registry.at('SingletonClass.bar').visibility).to     eq visibility
      expect(Registry.at('SingletonClass.baz').visibility).to     eq visibility
      expect(Registry.at('SingletonClass.bat').visibility).not_to eq visibility
    end
  end unless LEGACY_PARSER # reopened class

  describe "as method definition decorator" do
    subject { Registry.at('SingletonClass.foo') }

    # Valid as of Ruby 2.1.0:
    # private_class_method def self.foo; end

    let(:code) do
      <<-CODE
        class SingletonClass
          # Valid Ruby 2.1.0 syntax.
          #{method_def}
            'it works'
          end
        end
      CODE
    end

    let(:method_def) { "#{visibility}_class_method def self.foo param1, param2" }

    before { StubbedSourceParser.parse_string code }

    it "handles self.foo" do
      expect(subject.visibility).to eq visibility
    end

    it "handles parameters correctly" do
      expect(subject.parameters.map(&:first)).to eq ['param1', 'param2']
    end

    it "attaches documentation to method definition" do
      expect(subject.docstring).to eq "Valid Ruby 2.1.0 syntax."
    end

    describe "handles SingletonClass.foo" do
      let(:method_def) { "#{visibility}_class_method def SingletonClass.foo" }

      specify do
        expect(subject.visibility).to eq visibility
      end
    end
  end unless LEGACY_PARSER
end
