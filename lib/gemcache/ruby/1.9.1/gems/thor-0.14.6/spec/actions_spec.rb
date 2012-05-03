require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Thor::Actions do
  def runner(options={})
    @runner ||= MyCounter.new([1], options, { :destination_root => destination_root })
  end

  def action(*args, &block)
    capture(:stdout){ runner.send(*args, &block) }
  end

  def file
    File.join(destination_root, "foo")
  end

  describe "on include" do
    it "adds runtime options to the base class" do
      MyCounter.class_options.keys.should include(:pretend)
      MyCounter.class_options.keys.should include(:force)
      MyCounter.class_options.keys.should include(:quiet)
      MyCounter.class_options.keys.should include(:skip)
    end
  end

  describe "#initialize" do
    it "has default behavior invoke" do
      runner.behavior.should == :invoke
    end

    it "can have behavior revoke" do
      MyCounter.new([1], {}, :behavior => :revoke).behavior.should == :revoke
    end

    it "when behavior is set to force, overwrite options" do
      runner = MyCounter.new([1], { :force => false, :skip => true }, :behavior => :force)
      runner.behavior.should == :invoke
      runner.options.force.should be_true
      runner.options.skip.should_not be_true
    end

    it "when behavior is set to skip, overwrite options" do
      runner = MyCounter.new([1], ["--force"], :behavior => :skip)
      runner.behavior.should == :invoke
      runner.options.force.should_not be_true
      runner.options.skip.should be_true
    end
  end

  describe "accessors" do
    describe "#destination_root=" do
      it "gets the current directory and expands the path to set the root" do
        base = MyCounter.new([1])
        base.destination_root = "here"
        base.destination_root.should == File.expand_path(File.join(File.dirname(__FILE__), "..", "here"))
      end

      it "does not use the current directory if one is given" do
        root = File.expand_path("/")
        base = MyCounter.new([1])
        base.destination_root = root
        base.destination_root.should == root
      end

      it "uses the current directory if none is given" do
        base = MyCounter.new([1])
        base.destination_root.should == File.expand_path(File.join(File.dirname(__FILE__), ".."))
      end
    end

    describe "#relative_to_original_destination_root" do
      it "returns the path relative to the absolute root" do
        runner.relative_to_original_destination_root(file).should == "foo"
      end

      it "does not remove dot if required" do
        runner.relative_to_original_destination_root(file, false).should == "./foo"
      end

      it "always use the absolute root" do
        runner.inside("foo") do
          runner.relative_to_original_destination_root(file).should == "foo"
        end
      end

      describe "#source_paths_for_search" do
        it "add source_root to source_paths_for_search" do
          MyCounter.source_paths_for_search.should include(File.expand_path("fixtures", File.dirname(__FILE__)))
        end

        it "keeps only current source root in source paths" do
          ClearCounter.source_paths_for_search.should include(File.expand_path("fixtures/bundle", File.dirname(__FILE__)))
          ClearCounter.source_paths_for_search.should_not include(File.expand_path("fixtures", File.dirname(__FILE__)))
        end

        it "customized source paths should be before source roots" do
          ClearCounter.source_paths_for_search[0].should == File.expand_path("fixtures/doc", File.dirname(__FILE__))
          ClearCounter.source_paths_for_search[1].should == File.expand_path("fixtures/bundle", File.dirname(__FILE__))
        end

        it "keeps inherited source paths at the end" do
          ClearCounter.source_paths_for_search.last.should == File.expand_path("fixtures/broken", File.dirname(__FILE__))
        end
      end
    end

    describe "#find_in_source_paths" do
      it "raises an error if source path is empty" do
        lambda {
          A.new.find_in_source_paths("foo")
        }.should raise_error(Thor::Error, /Currently you have no source paths/)
      end

      it "finds a template inside the source path" do
        runner.find_in_source_paths("doc").should == File.expand_path("doc", source_root)
        lambda { runner.find_in_source_paths("README") }.should raise_error

        new_path = File.join(source_root, "doc")
        runner.instance_variable_set(:@source_paths, nil)
        runner.source_paths.unshift(new_path)
        runner.find_in_source_paths("README").should == File.expand_path("README", new_path)
      end
    end
  end

  describe "#inside" do
    it "executes the block inside the given folder" do
      runner.inside("foo") do
        Dir.pwd.should == file
      end
    end

    it "changes the base root" do
      runner.inside("foo") do
        runner.destination_root.should == file
      end
    end

    it "creates the directory if it does not exist" do
      runner.inside("foo") do
        File.exists?(file).should be_true
      end
    end

    describe "when pretending" do
      it "no directories should be created" do
        runner.inside("bar", :pretend => true) {}
        File.exists?("bar").should be_false
      end
    end

    describe "when verbose" do
      it "logs status" do
        capture(:stdout) do
          runner.inside("foo", :verbose => true) {}
        end.should =~ /inside  foo/
      end

      it "uses padding in next status" do
        capture(:stdout) do
          runner.inside("foo", :verbose => true) do
            runner.say_status :cool, :padding
          end
        end.should =~ /cool    padding/
      end

      it "removes padding after block" do
        capture(:stdout) do
          runner.inside("foo", :verbose => true) {}
          runner.say_status :no, :padding
        end.should =~ /no  padding/
      end
    end
  end

  describe "#in_root" do
    it "executes the block in the root folder" do
      runner.inside("foo") do
        runner.in_root { Dir.pwd.should == destination_root }
      end
    end

    it "changes the base root" do
      runner.inside("foo") do
        runner.in_root { runner.destination_root.should == destination_root }
      end
    end

    it "returns to the previous state" do
      runner.inside("foo") do
        runner.in_root { }
        runner.destination_root.should == file
      end
    end
  end

  describe "#apply" do
    before(:each) do
      @template = <<-TEMPLATE
        @foo = "FOO"
        say_status :cool, :padding
      TEMPLATE
      @template.stub(:read).and_return(@template)

      @file = '/'
      runner.stub(:open).and_return(@template)
    end

    it "accepts a URL as the path" do
      @file = "http://gist.github.com/103208.txt"
      runner.should_receive(:open).with(@file, "Accept" => "application/x-thor-template").and_return(@template)
      action(:apply, @file)
    end

    it "accepts a secure URL as the path" do
      @file = "https://gist.github.com/103208.txt"
      runner.should_receive(:open).with(@file, "Accept" => "application/x-thor-template").and_return(@template)
      action(:apply, @file)
    end

    it "accepts a local file path with spaces" do
      @file = File.expand_path("fixtures/path with spaces", File.dirname(__FILE__))
      runner.should_receive(:open).with(@file).and_return(@template)
      action(:apply, @file)
    end

    it "opens a file and executes its content in the instance binding" do
      action :apply, @file
      runner.instance_variable_get("@foo").should == "FOO"
    end

    it "applies padding to the content inside the file" do
      action(:apply, @file).should =~ /cool    padding/
    end

    it "logs its status" do
      action(:apply, @file).should =~ /       apply  #{@file}\n/
    end

    it "does not log status" do
      content = action(:apply, @file, :verbose => false)
      content.should =~ /cool  padding/
      content.should_not =~ /apply http/
    end
  end

  describe "#run" do
    before(:each) do
      runner.should_receive(:system).with("ls")
    end

    it "executes the command given" do
      action :run, "ls"
    end

    it "logs status" do
      action(:run, "ls").should == "         run  ls from \".\"\n"
    end

    it "does not log status if required" do
      action(:run, "ls", :verbose => false).should be_empty
    end

    it "accepts a color as status" do
      runner.shell.should_receive(:say_status).with(:run, 'ls from "."', :yellow)
      action :run, "ls", :verbose => :yellow
    end
  end

  describe "#run_ruby_script" do
    before(:each) do
      Thor::Util.stub!(:ruby_command).and_return("/opt/jruby")
      runner.should_receive(:system).with("/opt/jruby script.rb")
    end

    it "executes the ruby script" do
      action :run_ruby_script, "script.rb"
    end

    it "logs status" do
      action(:run_ruby_script, "script.rb").should == "         run  jruby script.rb from \".\"\n"
    end

    it "does not log status if required" do
      action(:run_ruby_script, "script.rb", :verbose => false).should be_empty
    end
  end

  describe "#thor" do
    it "executes the thor command" do
      runner.should_receive(:system).with("thor list")
      action :thor, :list, :verbose => true
    end

    it "converts extra arguments to command arguments" do
      runner.should_receive(:system).with("thor list foo bar")
      action :thor, :list, "foo", "bar"
    end

    it "converts options hash to switches" do
      runner.should_receive(:system).with("thor list foo bar --foo")
      action :thor, :list, "foo", "bar", :foo => true

      runner.should_receive(:system).with("thor list --foo 1 2 3")
      action :thor, :list, :foo => [1,2,3]
    end

    it "logs status" do
      runner.should_receive(:system).with("thor list")
      action(:thor, :list).should == "         run  thor list from \".\"\n"
    end

    it "does not log status if required" do
      runner.should_receive(:system).with("thor list --foo 1 2 3")
      action(:thor, :list, :foo => [1,2,3], :verbose => false).should be_empty
    end

    it "captures the output when :capture is given" do
      runner.should_receive(:`).with("thor foo bar")
      action(:thor, "foo", "bar", :capture => true)
    end
  end
end
