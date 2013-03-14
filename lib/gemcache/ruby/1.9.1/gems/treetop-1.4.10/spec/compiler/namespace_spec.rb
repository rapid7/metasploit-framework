require 'spec_helper'

module NamespaceSpec

  describe "a grammar" do
    class_eval("module Foo; end")
    testing_grammar %{
      module Foo::Bar
        module Baz
          grammar Bat
            rule foo
              bar / baz
            end

            rule bar
              'bar' 'bar'
            end

            rule baz
              'baz' 'baz'
            end
          end
        end
      end
    }

    it "parses matching input" do
      parse('barbar').should_not be_nil
      parse('bazbaz').should_not be_nil
    end

    it "mixes in included modules" do
      foo = self.class.const_get(:Foo)
      bar = foo.const_get(:Bar)
      baz = bar.const_get(:Baz)
      baz.class.should == Module
      bat = baz.const_get(:Bat)
      bat.class.should == Module
      baz.const_get(:BatParser).class.should == Class
    end
  end
end
