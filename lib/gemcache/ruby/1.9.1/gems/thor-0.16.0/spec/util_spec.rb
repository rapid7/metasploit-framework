require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Thor::Util
  def self.clear_user_home!
    @@user_home = nil
  end
end

describe Thor::Util do
  describe "#find_by_namespace" do
    it "returns 'default' if no namespace is given" do
      Thor::Util.find_by_namespace('').should == Scripts::MyDefaults
    end

    it "adds 'default' if namespace starts with :" do
      Thor::Util.find_by_namespace(':child').should == Scripts::ChildDefault
    end

    it "returns nil if the namespace can't be found" do
      Thor::Util.find_by_namespace('thor:core_ext:ordered_hash').should be_nil
    end

    it "returns a class if it matches the namespace" do
      Thor::Util.find_by_namespace('app:broken:counter').should == BrokenCounter
    end

    it "matches classes default namespace" do
      Thor::Util.find_by_namespace('scripts:my_script').should == Scripts::MyScript
    end
  end

  describe "#namespace_from_thor_class" do
    it "replaces constant nesting with task namespacing" do
      Thor::Util.namespace_from_thor_class("Foo::Bar::Baz").should == "foo:bar:baz"
    end

    it "snake-cases component strings" do
      Thor::Util.namespace_from_thor_class("FooBar::BarBaz::BazBoom").should == "foo_bar:bar_baz:baz_boom"
    end

    it "accepts class and module objects" do
      Thor::Util.namespace_from_thor_class(Thor::CoreExt::OrderedHash).should == "thor:core_ext:ordered_hash"
      Thor::Util.namespace_from_thor_class(Thor::Util).should == "thor:util"
    end

    it "removes Thor::Sandbox namespace" do
      Thor::Util.namespace_from_thor_class("Thor::Sandbox::Package").should == "package"
    end
  end

  describe "#namespaces_in_content" do
    it "returns an array of names of constants defined in the string" do
      list = Thor::Util.namespaces_in_content("class Foo; class Bar < Thor; end; end; class Baz; class Bat; end; end")
      list.should include("foo:bar")
      list.should_not include("bar:bat")
    end

    it "doesn't put the newly-defined constants in the enclosing namespace" do
      Thor::Util.namespaces_in_content("class Blat; end")
      defined?(Blat).should_not be
      defined?(Thor::Sandbox::Blat).should be
    end
  end

  describe "#snake_case" do
    it "preserves no-cap strings" do
      Thor::Util.snake_case("foo").should == "foo"
      Thor::Util.snake_case("foo_bar").should == "foo_bar"
    end

    it "downcases all-caps strings" do
      Thor::Util.snake_case("FOO").should == "foo"
      Thor::Util.snake_case("FOO_BAR").should == "foo_bar"
    end

    it "downcases initial-cap strings" do
      Thor::Util.snake_case("Foo").should == "foo"
    end

    it "replaces camel-casing with underscores" do
      Thor::Util.snake_case("FooBarBaz").should == "foo_bar_baz"
      Thor::Util.snake_case("Foo_BarBaz").should == "foo_bar_baz"
    end

    it "places underscores between multiple capitals" do
      Thor::Util.snake_case("ABClass").should == "a_b_class"
    end
  end

  describe "#find_class_and_task_by_namespace" do
    it "returns a Thor::Group class if full namespace matches" do
      Thor::Util.find_class_and_task_by_namespace("my_counter").should == [MyCounter, nil]
    end

    it "returns a Thor class if full namespace matches" do
      Thor::Util.find_class_and_task_by_namespace("thor").should == [Thor, nil]
    end

    it "returns a Thor class and the task name" do
      Thor::Util.find_class_and_task_by_namespace("thor:help").should == [Thor, "help"]
    end

    it "falls back in the namespace:task look up even if a full namespace does not match" do
      Thor.const_set(:Help, Module.new)
      Thor::Util.find_class_and_task_by_namespace("thor:help").should == [Thor, "help"]
      Thor.send :remove_const, :Help
    end

    it "falls back on the default namespace class if nothing else matches" do
      Thor::Util.find_class_and_task_by_namespace("test").should == [Scripts::MyDefaults, "test"]
    end
  end

  describe "#thor_classes_in" do
    it "returns thor classes inside the given class" do
      Thor::Util.thor_classes_in(MyScript).should == [MyScript::AnotherScript]
      Thor::Util.thor_classes_in(MyScript::AnotherScript).should be_empty
    end
  end

  describe "#user_home" do
    before do
      ENV.stub!(:[])
      Thor::Util.clear_user_home!
    end

    it "returns the user path if none variable is set on the environment" do
      Thor::Util.user_home.should == File.expand_path("~")
    end

    it "returns the *unix system path if file cannot be expanded and separator does not exist" do
      File.should_receive(:expand_path).with("~").and_raise(RuntimeError)
      previous_value = File::ALT_SEPARATOR
      capture(:stderr){ File.const_set(:ALT_SEPARATOR, false) }
      Thor::Util.user_home.should == "/"
      capture(:stderr){ File.const_set(:ALT_SEPARATOR, previous_value) }
    end

    it "returns the windows system path if file cannot be expanded and a separator exists" do
      File.should_receive(:expand_path).with("~").and_raise(RuntimeError)
      previous_value = File::ALT_SEPARATOR
      capture(:stderr){ File.const_set(:ALT_SEPARATOR, true) }
      Thor::Util.user_home.should == "C:/"
      capture(:stderr){ File.const_set(:ALT_SEPARATOR, previous_value) }
    end

    it "returns HOME/.thor if set" do
      ENV.stub!(:[]).with("HOME").and_return("/home/user/")
      Thor::Util.user_home.should == "/home/user/"
    end

    it "returns path with HOMEDRIVE and HOMEPATH if set" do
      ENV.stub!(:[]).with("HOMEDRIVE").and_return("D:/")
      ENV.stub!(:[]).with("HOMEPATH").and_return("Documents and Settings/James")
      Thor::Util.user_home.should == "D:/Documents and Settings/James"
    end

    it "returns APPDATA/.thor if set" do
      ENV.stub!(:[]).with("APPDATA").and_return("/home/user/")
      Thor::Util.user_home.should == "/home/user/"
    end
  end

  describe "#thor_root_glob" do
    before do
      ENV.stub!(:[])
      Thor::Util.clear_user_home!
    end

    it "escapes globs in path" do
      ENV.stub!(:[]).with("HOME").and_return("/home/user{1}/")
      Dir.should_receive(:[]).with("/home/user\\{1\\}/.thor/*").and_return([])
      Thor::Util.thor_root_glob.should == []
    end
  end

  describe "#globs_for" do
    it "escapes globs in path" do
      Thor::Util.globs_for("/home/apps{1}").should == [
        "/home/apps\\{1\\}/Thorfile",
        "/home/apps\\{1\\}/*.thor",
        "/home/apps\\{1\\}/tasks/*.thor",
        "/home/apps\\{1\\}/lib/tasks/*.thor"
      ]
    end
  end

  describe "#escape_globs" do
    it "escapes ? * { } [ ] glob characters" do
      Thor::Util.escape_globs("apps?").should == "apps\\?"
      Thor::Util.escape_globs("apps*").should == "apps\\*"
      Thor::Util.escape_globs("apps {1}").should == "apps \\{1\\}"
      Thor::Util.escape_globs("apps [1]").should == "apps \\[1\\]"
    end
  end
end
