require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Thor do
  describe "#method_option" do
    it "sets options to the next method to be invoked" do
      args = ["foo", "bar", "--force"]
      arg, options = MyScript.start(args)
      options.should == { "force" => true }
    end

    describe ":lazy_default" do
      it "is absent when option is not specified" do
        arg, options = MyScript.start(["with_optional"])
        options.should == {}
      end

      it "sets a default that can be overridden for strings" do
        arg, options = MyScript.start(["with_optional", "--lazy"])
        options.should == { "lazy" => "yes" }

        arg, options = MyScript.start(["with_optional", "--lazy", "yesyes!"])
        options.should == { "lazy" => "yesyes!" }
      end

      it "sets a default that can be overridden for numerics" do
        arg, options = MyScript.start(["with_optional", "--lazy-numeric"])
        options.should == { "lazy_numeric" => 42 }

        arg, options = MyScript.start(["with_optional", "--lazy-numeric", 20000])
        options.should == { "lazy_numeric" => 20000 }
      end

      it "sets a default that can be overridden for arrays" do
        arg, options = MyScript.start(["with_optional", "--lazy-array"])
        options.should == { "lazy_array" => %w[eat at joes] }

        arg, options = MyScript.start(["with_optional", "--lazy-array", "hello", "there"])
        options.should == { "lazy_array" => %w[hello there] }
      end

      it "sets a default that can be overridden for hashes" do
        arg, options = MyScript.start(["with_optional", "--lazy-hash"])
        options.should == { "lazy_hash" => {'swedish' => 'meatballs'} }

        arg, options = MyScript.start(["with_optional", "--lazy-hash", "polish:sausage"])
        options.should == { "lazy_hash" => {'polish' => 'sausage'} }
      end
    end

    describe "when :for is supplied" do
      it "updates an already defined task" do
        args, options = MyChildScript.start(["animal", "horse", "--other=fish"])
        options[:other].should == "fish"
      end

      describe "and the target is on the parent class" do
        it "updates an already defined task" do
          args = ["example_default_task", "my_param", "--new-option=verified"]
          options = Scripts::MyScript.start(args)
          options[:new_option].should == "verified"
        end

        it "adds a task to the tasks list if the updated task is on the parent class" do
          Scripts::MyScript.tasks["example_default_task"].should be
        end

        it "clones the parent task" do
          Scripts::MyScript.tasks["example_default_task"].should_not == MyChildScript.tasks["example_default_task"]
        end
      end
    end
  end

  describe "#default_task" do
    it "sets a default task" do
      MyScript.default_task.should == "example_default_task"
    end

    it "invokes the default task if no command is specified" do
      MyScript.start([]).should == "default task"
    end

    it "invokes the default task if no command is specified even if switches are given" do
      MyScript.start(["--with", "option"]).should == {"with"=>"option"}
    end

    it "inherits the default task from parent" do
      MyChildScript.default_task.should == "example_default_task"
    end
  end

  describe "#map" do
    it "calls the alias of a method if one is provided" do
      MyScript.start(["-T", "fish"]).should == ["fish"]
    end

    it "calls the alias of a method if several are provided via .map" do
      MyScript.start(["-f", "fish"]).should == ["fish", {}]
      MyScript.start(["--foo", "fish"]).should == ["fish", {}]
    end

    it "inherits all mappings from parent" do
      MyChildScript.default_task.should == "example_default_task"
    end
  end

  describe "#desc" do
    it "provides description for a task" do
      content = capture(:stdout) { MyScript.start(["help"]) }
      content.should =~ /thor my_script:zoo\s+# zoo around/m
    end

    it "provides no namespace if $thor_runner is false" do
      begin
        $thor_runner = false
        content = capture(:stdout) { MyScript.start(["help"]) }
        content.should =~ /thor zoo\s+# zoo around/m
      ensure
        $thor_runner = true
      end
    end

    describe "when :for is supplied" do
      it "overwrites a previous defined task" do
        capture(:stdout) { MyChildScript.start(["help"]) }.should =~ /animal KIND \s+# fish around/m
      end
    end

    describe "when :hide is supplied" do
      it "does not show the task in help" do
        capture(:stdout) { MyScript.start(["help"]) }.should_not =~ /this is hidden/m
      end

      it "but the task is still invokcable not show the task in help" do
        MyScript.start(["hidden", "yesyes"]).should == ["yesyes"]
      end
    end
  end

  describe "#method_options" do
    it "sets default options if called before an initializer" do
      options = MyChildScript.class_options
      options[:force].type.should == :boolean
      options[:param].type.should == :numeric
    end

    it "overwrites default options if called on the method scope" do
      args = ["zoo", "--force", "--param", "feathers"]
      options = MyChildScript.start(args)
      options.should == { "force" => true, "param" => "feathers" }
    end

    it "allows default options to be merged with method options" do
      args = ["animal", "bird", "--force", "--param", "1.0", "--other", "tweets"]
      arg, options = MyChildScript.start(args)
      arg.should == 'bird'
      options.should == { "force"=>true, "param"=>1.0, "other"=>"tweets" }
    end
  end

  describe "#start" do
    it "calls a no-param method when no params are passed" do
      MyScript.start(["zoo"]).should == true
    end

    it "calls a single-param method when a single param is passed" do
      MyScript.start(["animal", "fish"]).should == ["fish"]
    end

    it "does not set options in attributes" do
      MyScript.start(["with_optional", "--all"]).should == [nil, { "all" => true }, []]
    end

    it "raises an error if a required param is not provided" do
      capture(:stderr) { MyScript.start(["animal"]) }.strip.should == 'thor animal requires at least 1 argument: "thor my_script:animal TYPE".'
    end

    it "raises an error if the invoked task does not exist" do
      capture(:stderr) { Amazing.start(["animal"]) }.strip.should == 'Could not find task "animal" in "amazing" namespace.'
    end

    it "calls method_missing if an unknown method is passed in" do
      MyScript.start(["unk", "hello"]).should == [:unk, ["hello"]]
    end

    it "does not call a private method no matter what" do
      capture(:stderr) { MyScript.start(["what"]) }.strip.should == 'Could not find task "what" in "my_script" namespace.'
    end

    it "uses task default options" do
      options = MyChildScript.start(["animal", "fish"]).last
      options.should == { "other" => "method default" }
    end

    it "raises when an exception happens within the task call" do
      lambda { MyScript.start(["call_myself_with_wrong_arity"]) }.should raise_error(ArgumentError)
    end

    context "when the user enters an unambiguous substring of a command" do
      it "should invoke a command" do
        MyScript.start(["z"]).should == MyScript.start(["zoo"])
      end

      it "should invoke a command, even when there's an alias the resolves to the same command" do
        MyScript.start(["hi"]).should == MyScript.start(["hidden"])
      end

      it "should invoke an alias" do
        MyScript.start(["animal_pri"]).should == MyScript.start(["zoo"])
      end
    end

    context "when the user enters an ambiguous substring of a command" do
      it "should raise an exception that explains the ambiguity" do
        lambda { MyScript.start(["call"]) }.should raise_error(ArgumentError, 'Ambiguous task call matches [call_myself_with_wrong_arity, call_unexistent_method]')
      end

      it "should raise an exception when there is an alias" do
        lambda { MyScript.start(["f"]) }.should raise_error(ArgumentError, 'Ambiguous task f matches [foo, fu]')
      end
    end

  end

  describe "#subcommand" do
    it "maps a given subcommand to another Thor subclass" do
      barn_help = capture(:stdout){ Scripts::MyDefaults.start(["barn"]) }
      barn_help.should include("barn help [COMMAND]  # Describe subcommands or one specific subcommand")
    end

    it "passes commands to subcommand classes" do
      capture(:stdout){ Scripts::MyDefaults.start(["barn", "open"]) }.strip.should == "Open sesame!"
    end

    it "passes arguments to subcommand classes" do
      capture(:stdout){ Scripts::MyDefaults.start(["barn", "open", "shotgun"]) }.strip.should == "That's going to leave a mark."
    end

    it "ignores unknown options (the subcommand class will handle them)" do
      capture(:stdout){ Scripts::MyDefaults.start(["barn", "paint", "blue", "--coats", "4"])}.strip.should == "4 coats of blue paint"
    end
  end

  describe "#help" do
    def shell
      @shell ||= Thor::Base.shell.new
    end

    describe "on general" do
      before do
        @content = capture(:stdout){ MyScript.help(shell) }
      end

      it "provides useful help info for the help method itself" do
        @content.should =~ /help \[TASK\]\s+# Describe available tasks/
      end

      it "provides useful help info for a method with params" do
        @content.should =~ /animal TYPE\s+# horse around/
      end

      it "uses the maximum terminal size to show tasks" do
        @shell.should_receive(:terminal_width).and_return(80)
        content = capture(:stdout){ MyScript.help(shell) }
        content.should =~ /aaa\.\.\.$/
      end

      it "provides description for tasks from classes in the same namespace" do
        @content.should =~ /baz\s+# do some bazing/
      end

      it "shows superclass tasks" do
        content = capture(:stdout){ MyChildScript.help(shell) }
        content.should =~ /foo BAR \s+# do some fooing/
      end

      it "shows class options information" do
        content = capture(:stdout){ MyChildScript.help(shell) }
        content.should =~ /Options\:/
        content.should =~ /\[\-\-param=N\]/
      end

      it "injects class arguments into default usage" do
        content = capture(:stdout){ Scripts::MyScript.help(shell) }
        content.should =~ /zoo ACCESSOR \-\-param\=PARAM/
      end
    end

    describe "for a specific task" do
      it "provides full help info when talking about a specific task" do
        capture(:stdout) { MyScript.task_help(shell, "foo") }.should == <<-END
Usage:
  thor my_script:foo BAR

Options:
  [--force]  # Force to do some fooing

do some fooing
  This is more info!
  Everyone likes more info!
END
      end

      it "raises an error if the task can't be found" do
        lambda {
          MyScript.task_help(shell, "unknown")
        }.should raise_error(Thor::UndefinedTaskError, 'Could not find task "unknown" in "my_script" namespace.')
      end

      it "normalizes names before claiming they don't exist" do
        capture(:stdout) { MyScript.task_help(shell, "name-with-dashes") }.should =~ /thor my_script:name-with-dashes/
      end

      it "uses the long description if it exists" do
        capture(:stdout) { MyScript.task_help(shell, "long_description") }.should == <<-HELP
Usage:
  thor my_script:long_description

Description:
  This is a really really really long description. Here you go. So very long.

  It even has two paragraphs.
HELP
      end

      it "doesn't assign the long description to the next task without one" do
        capture(:stdout) do
          MyScript.task_help(shell, "name_with_dashes")
        end.should_not =~ /so very long/i
      end
    end

    describe "instance method" do
      it "calls the class method" do
        capture(:stdout){ MyScript.start(["help"]) }.should =~ /Tasks:/
      end

      it "calls the class method" do
        capture(:stdout){ MyScript.start(["help", "foo"]) }.should =~ /Usage:/
      end
    end
  end

  describe "when creating tasks" do
    it "prints a warning if a public method is created without description or usage" do
      capture(:stdout) {
        klass = Class.new(Thor)
        klass.class_eval "def hello_from_thor; end"
      }.should =~ /\[WARNING\] Attempted to create task "hello_from_thor" without usage or description/
    end

    it "does not print if overwriting a previous task" do
      capture(:stdout) {
        klass = Class.new(Thor)
        klass.class_eval "def help; end"
      }.should be_empty
    end
  end

  describe "edge-cases" do
    it "can handle boolean options followed by arguments" do
      klass = Class.new(Thor) do
        method_option :loud, :type => :boolean
        desc "hi NAME", "say hi to name"
        def hi(name)
          name.upcase! if options[:loud]
          "Hi #{name}"
        end
      end

      klass.start(["hi", "jose"]).should == "Hi jose"
      klass.start(["hi", "jose", "--loud"]).should == "Hi JOSE"
      klass.start(["hi", "--loud", "jose"]).should == "Hi JOSE"
    end

    it "passes through unknown options" do
      klass = Class.new(Thor) do
        desc "unknown", "passing unknown options"
        def unknown(*args)
          args
        end
      end

      klass.start(["unknown", "foo", "--bar", "baz", "bat", "--bam"]).should == ["foo", "--bar", "baz", "bat", "--bam"]
      klass.start(["unknown", "--bar", "baz"]).should == ["--bar", "baz"]
    end

    it "does not pass through unknown options with strict args" do
      klass = Class.new(Thor) do
        strict_args_position!

        desc "unknown", "passing unknown options"
        def unknown(*args)
          args
        end
      end

      klass.start(["unknown", "--bar", "baz"]).should == []
      klass.start(["unknown", "foo", "--bar", "baz"]).should == ["foo"]
    end

    it "strict args works in the inheritance chain" do
      parent = Class.new(Thor) do
        strict_args_position!
      end

      klass = Class.new(parent) do
        desc "unknown", "passing unknown options"
        def unknown(*args)
          args
        end
      end

      klass.start(["unknown", "--bar", "baz"]).should == []
      klass.start(["unknown", "foo", "--bar", "baz"]).should == ["foo"]
    end
  end
end
