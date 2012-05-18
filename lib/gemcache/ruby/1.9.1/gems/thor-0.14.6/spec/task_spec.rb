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
      Object.stub!(:namespace).and_return("foo")
      Object.stub!(:arguments).and_return([])
      task(:bar => :required).formatted_usage(Object).should == "foo:can_has --bar=BAR"
    end

    it "removes default from namespace" do
      Object.stub!(:namespace).and_return("default:foo")
      Object.stub!(:arguments).and_return([])
      task(:bar => :required).formatted_usage(Object).should == ":foo:can_has --bar=BAR"
    end

    it "injects arguments into usage" do
      Object.stub!(:namespace).and_return("foo")
      Object.stub!(:arguments).and_return([ Thor::Argument.new(:bar, nil, true, :string) ])
      task(:foo => :required).formatted_usage(Object).should == "foo:can_has BAR --foo=FOO"
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
      task.options[:foo].should_not be_nil
    end
  end

  describe "#run" do
    it "runs a task by calling a method in the given instance" do
      mock = mock()
      mock.should_receive(:send).with("can_has", 1, 2, 3)
      task.run(mock, [1, 2, 3])
    end

    it "raises an error if the method to be invoked is private" do
      mock = mock()
      mock.should_receive(:private_methods).and_return(['can_has'])
      mock.class.should_receive(:handle_no_task_error).with("can_has")
      task.run(mock)
    end
  end
end
