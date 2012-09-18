class MyScript < Thor
  check_unknown_options! :except => :with_optional

  attr_accessor :some_attribute
  attr_writer :another_attribute
  attr_reader :another_attribute

  group :script
  default_task :example_default_task

  map "-T" => :animal, ["-f", "--foo"] => :foo

  map "animal_prison" => "zoo"

  desc "zoo", "zoo around"
  def zoo
    true
  end

  desc "animal TYPE", "horse around"

  no_tasks do
    def this_is_not_a_task
    end
  end

  def animal(type)
    [type]
  end

  map "hid" => "hidden"

  desc "hidden TYPE", "this is hidden", :hide => true
  def hidden(type)
    [type]
  end

  map "fu" => "zoo"

  desc "foo BAR", <<END
do some fooing
  This is more info!
  Everyone likes more info!
END
  method_option :force, :type => :boolean, :desc => "Force to do some fooing"
  def foo(bar)
    [bar, options]
  end

  desc "example_default_task", "example!"
  method_options :with => :string
  def example_default_task
    options.empty? ? "default task" : options
  end

  desc "call_myself_with_wrong_arity", "get the right error"
  def call_myself_with_wrong_arity
    call_myself_with_wrong_arity(4)
  end

  desc "call_unexistent_method", "Call unexistent method inside a task"
  def call_unexistent_method
    boom!
  end

  desc "long_description", "a" * 80
  long_desc <<-D
    This is a really really really long description.
    Here you go. So very long.

    It even has two paragraphs.
  D
  def long_description
  end

  desc "name-with-dashes", "Ensure normalization of task names"
  def name_with_dashes
  end

  method_options :all => :boolean
  method_option :lazy, :lazy_default => "yes"
  method_option :lazy_numeric, :type => :numeric, :lazy_default => 42
  method_option :lazy_array,   :type => :array,   :lazy_default => %w[eat at joes]
  method_option :lazy_hash,    :type => :hash,    :lazy_default => {'swedish' => 'meatballs'}
  desc "with_optional NAME", "invoke with optional name"
  def with_optional(name=nil, *args)
    [ name, options, args ]
  end

  class AnotherScript < Thor
    desc "baz", "do some bazing"
    def baz
    end
  end

  private

    def method_missing(meth, *args)
      if meth == :boom!
        super
      else
        [meth, args]
      end
    end

    desc "what", "what"
    def what
    end
end

class MyChildScript < MyScript
  remove_task :bar

  method_options :force => :boolean, :param => :numeric
  def initialize(*args)
    super
  end

  desc "zoo", "zoo around"
  method_options :param => :required
  def zoo
    options
  end

  desc "animal TYPE", "horse around"
  def animal(type)
    [type, options]
  end
  method_option :other, :type => :string, :default => "method default", :for => :animal
  desc "animal KIND", "fish around", :for => :animal

  desc "boom", "explodes everything"
  def boom
  end

  remove_task :boom, :undefine => true
end

class Barn < Thor
  desc "open [ITEM]", "open the barn door"
  def open(item = nil)
    if item == "shotgun"
      puts "That's going to leave a mark."
    else
      puts "Open sesame!"
    end
  end

  desc "paint [COLOR]", "paint the barn"
  method_option :coats, :type => :numeric, :default => 2, :desc => 'how many coats of paint'
  def paint(color='red')
    puts "#{options[:coats]} coats of #{color} paint"
  end

end

module Scripts
  class MyScript < MyChildScript
    argument :accessor, :type => :string
    class_options :force => :boolean
    method_option :new_option, :type => :string, :for => :example_default_task

    def zoo
      self.accessor
    end
  end

  class MyDefaults < Thor
    check_unknown_options!

    namespace :default
    desc "cow", "prints 'moo'"
    def cow
      puts "moo"
    end

    desc "task_conflict", "only gets called when prepended with a colon"
    def task_conflict
      puts "task"
    end

    desc "barn", "commands to manage the barn"
    subcommand "barn", Barn
  end

  class ChildDefault < Thor
    namespace "default:child"
  end
end

