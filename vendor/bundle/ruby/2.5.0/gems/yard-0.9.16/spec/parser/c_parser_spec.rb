# frozen_string_literal: true

RSpec.describe YARD::Parser::C::CParser do
  describe "#parse" do
    def parse(contents)
      Registry.clear
      YARD.parse_string(contents, :c)
    end

    describe "Array class" do
      before(:all) do
        file = File.join(File.dirname(__FILE__), 'examples', 'array.c.txt')
        parse(File.read(file))
      end

      it "parses Array class" do
        obj = YARD::Registry.at('Array')
        expect(obj).not_to be nil
        expect(obj.docstring).not_to be_blank
      end

      it "parses method" do
        obj = YARD::Registry.at('Array#initialize')
        expect(obj.docstring).not_to be_blank
        expect(obj.tags(:overload).size).to be > 1
      end

      it "parses new_ary return type" do
        obj = YARD::Registry.at('Array#map')
        expect(obj.tags(:overload).count do |overload|
          overload.tag(:return) && overload.tag(:return).types == ['Enumerator']
        end).to eq 2
        expect(obj.tags(:overload).count do |overload|
          overload.tag(:return) && overload.tag(:return).types == ['Array']
        end).to eq 2
      end
    end

    describe "C++ namespace" do
      before(:all) do
        file = File.join(File.dirname(__FILE__), 'examples', 'namespace.cpp.txt')
        parse(File.read(file))
      end

      it "parses Rect class" do
        obj = YARD::Registry.at('Rect')
        expect(obj).not_to be nil
        expect(obj.docstring).not_to be_blank
      end

      it "parses method inside of namespace" do
        obj = YARD::Registry.at('Rect#inspect')
        expect(obj.docstring).not_to be_blank
      end

      it "parses method after namespace" do
        obj = YARD::Registry.at('Rect#hello_world')
        expect(obj.docstring).not_to be_blank
      end
    end

    describe "Source located in extra files" do
      before(:all) do
        @multifile = File.join(File.dirname(__FILE__), 'examples', 'multifile.c.txt')
        @extrafile = File.join(File.dirname(__FILE__), 'examples', 'extrafile.c.txt')
        @contents = File.read(@multifile)
      end

      it "looks for methods in extra files (if 'in' comment is found)" do
        extra_contents = File.read(@extrafile)
        expect(File).to receive(:read).with('extra.c').and_return(extra_contents)
        parse(@contents)
        expect(Registry.at('Multifile#extra').docstring).to eq 'foo'
      end

      it "stops searching for extra source file gracefully if file is not found" do
        expect(File).to receive(:read).with('extra.c').and_raise(Errno::ENOENT)
        expect(log).to receive(:warn).with("Missing source file `extra.c' when parsing Multifile#extra")
        parse(@contents)
        expect(Registry.at('Multifile#extra').docstring).to eq ''
      end

      it "differentiates between a struct and a pointer to a struct retval" do
        parse(@contents)
        expect(Registry.at('Multifile#hello_mars').docstring).to eq 'Hello Mars'
      end
    end

    describe "Foo class" do
      it "does not include comments in docstring source" do
        parse <<-eof
          /*
           * Hello world
           */
          VALUE foo(VALUE x) {
            int value = x;
          }

          void Init_Foo() {
            rb_define_method(rb_cFoo, "foo", foo, 1);
          }
        eof
        expect(Registry.at('Foo#foo').source.gsub(/\s\s+/, ' ')).to eq(
          "VALUE foo(VALUE x) { int value = x;\n}"
        )
      end
    end

    describe "Constant" do
      it "does not truncate docstring" do
        parse <<-eof
          #define MSK_DEADBEEF 0xdeadbeef
          void
          Init_Mask(void)
          {
              rb_cMask  = rb_define_class("Mask", rb_cObject);
              /* 0xdeadbeef: This constant is frequently used to indicate a
               * software crash or deadlock in embedded systems. */
              rb_define_const(rb_cMask, "DEADBEEF", INT2FIX(MSK_DEADBEEF));
          }
        eof
        constant = Registry.at('Mask::DEADBEEF')
        expect(constant.value).to eq '0xdeadbeef'
        expect(constant.docstring).to eq "This constant is frequently used to indicate a\nsoftware crash or deadlock in embedded systems."
      end
    end

    describe "Macros" do
      it "handles param## inside of macros" do
        thr = Thread.new do
          parse <<-eof
          void
          Init_gobject_gparamspecs(void)
          {
              VALUE cParamSpec = GTYPE2CLASS(G_TYPE_PARAM);
              VALUE c;

          #define DEF_NUMERIC_PSPEC_METHODS(c, typename) \
            G_STMT_START {\
              rbg_define_method(c, "initialize", typename##_initialize, 7); \
              rbg_define_method(c, "minimum", typename##_minimum, 0); \
              rbg_define_method(c, "maximum", typename##_maximum, 0); \
              rbg_define_method(c, "range", typename##_range, 0); \
            } G_STMT_END

          #if 0
              rbg_define_method(c, "default_value", typename##_default_value, 0); \
              rb_define_alias(c, "default", "default_value"); \

          #endif

              c = G_DEF_CLASS(G_TYPE_PARAM_CHAR, "Char", cParamSpec);
              DEF_NUMERIC_PSPEC_METHODS(c, char);
          eof
        end
        thr.join(5)
        if thr.alive?
          thr.kill
          raise "Did not parse in time"
        end
      end
    end

    describe "C macros in declaration" do
      it "handles C macros in method declaration" do
        Registry.clear
        parse <<-eof
        // docstring
        FOOBAR VALUE func() { }

        void
        Init_mod(void)
        {
          rb_define_method(rb_cFoo, "func", func, 0); \
        }
        eof

        expect(Registry.at('Foo#func').docstring).to eq "docstring"
      end
    end
  end

  describe "Override comments" do
    before(:all) do
      Registry.clear
      override_file = File.join(File.dirname(__FILE__), 'examples', 'override.c.txt')
      @override_parser = YARD.parse_string(File.read(override_file), :c)
    end

    it "parses GMP::Z class" do
      z = YARD::Registry.at('GMP::Z')
      expect(z).not_to be nil
      expect(z.docstring).not_to be_blank
    end

    it "parses GMP::Z methods w/ bodies" do
      add = YARD::Registry.at('GMP::Z#+')
      expect(add.docstring).not_to be_blank
      expect(add.source).not_to be nil
      expect(add.source).not_to be_empty

      add_self = YARD::Registry.at('GMP::Z#+')
      expect(add_self.docstring).not_to be_blank
      expect(add_self.source).not_to be nil
      expect(add_self.source).not_to be_empty

      sqrtrem = YARD::Registry.at('GMP::Z#+')
      expect(sqrtrem.docstring).not_to be_blank
      expect(sqrtrem.source).not_to be nil
      expect(sqrtrem.source).not_to be_empty
    end

    it "parses GMP::Z methods w/o bodies" do
      neg = YARD::Registry.at('GMP::Z#neg')
      expect(neg.docstring).not_to be_blank
      expect(neg.source).to be nil

      neg_self = YARD::Registry.at('GMP::Z#neg')
      expect(neg_self.docstring).not_to be_blank
      expect(neg_self.source).to be nil
    end
  end
end
