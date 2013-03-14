require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Thor::Task do
  def task(options={})
    options.each do |key, value|
      options[key] = Thor::Option.parse(key, value)
    end

    @task ||= Thor::Task.new(:can_has, "I can has cheezburger", "I can has cheezburger\nLots and lots of it", "can_has", options)
  end

  describe "#formatted_usage" do
    it "includes namespace within usage" do
      object = Struct.new(:namespace, :arguments).new("foo", [])
      task(:bar => :required).formatted_usage(object).should == "foo:can_has --bar=BAR"
    end

    it "includes subcommand name within subcommand usage" do
      object = Struct.new(:namespace, :arguments).new("main:foo", [])
      task(:bar => :required).formatted_usage(object, false, true).should == "foo can_has --bar=BAR"
    end

    it "removes default from namespace" do
      object = Struct.new(:namespace, :arguments).new("default:foo", [])
      task(:bar => :required).formatted_usage(object).should == ":foo:can_has --bar=BAR"
    end

    it "injects arguments into usage" do
      options = {:required => true, :type => :string}
      object = Struct.new(:namespace, :arguments).new("foo", [Thor::Argument.new(:bar, options)])
      task(:foo => :required).formatted_usage(object).should == "foo:can_has BAR --foo=FOO"
    end
  end

  describe "#dynamic" do
    it "creates a dynamic task with the given name" do
      Thor::DynamicTask.new('task').name.should == 'task'
      Thor::DynamicTask.new('task').description.should == 'A dynamically-generated task'
      Thor::DynamicTask.new('task').usage.should == 'task'
      Thor::DynamicTask.new('task').options.should == {}
    end

    it "does not invoke an existing method" do
      mock = mock()
      mock.class.should_receive(:handle_no_task_error).with("to_s")
      Thor::DynamicTask.new('to_s').run(mock)
    end
  end

  describe "#dup" do
    it "dup options hash" do
      task = Thor::Task.new("can_has", nil, nil, nil, :foo => true, :bar => :required)
      task.dup.options.delete(:foo)
      task.options[:foo].should be
    end
  end

  describe "#run" do
    it "runs a task by calling a method in the given instance" do
      mock = mock()
      mock.should_receive(:can_has).and_return {|*args| args }
      task.run(mock, [1, 2, 3]).should == [1, 2, 3]
    end

    it "raises an error if the method to be invoked is private" do
      klass = Class.new do
        def self.handle_no_task_error(name)
          name
        end

      private
        def can_has
          "fail"
        end
      end

      task.run(klass.new).should == "can_has"
    end
  end
end
