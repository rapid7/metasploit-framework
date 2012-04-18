# Thor 

## Description

Thor is a simple and efficient tool for building self-documenting command line utilities.  It removes the pain of parsing command line options, writing "USAGE:" banners, and can also be used as an alternative to the [Rake](http://github.com/jimweirich/rake) build tool.  The syntax is Rake-like, so it should be familiar to most Rake users. 

## Installation

$ gem install thor

or

$ gem install wycats-thor -s http://gems.github.com

## Usage

Map options to a class.  Simply create a class with the appropriate annotations
and have options automatically map to functions and parameters.  

Example:

    class App < Thor                                                 # [1]
      map "-L" => :list                                              # [2]
      
      desc "install APP_NAME", "install one of the available apps"   # [3]
      method_options :force => :boolean, :alias => :string           # [4]
      def install(name)
        user_alias = options[:alias]
        if options.force?
          # do something
        end
        # other code
      end
      
      desc "list [SEARCH]", "list all of the available apps, limited by SEARCH"
      def list(search="")
        # list everything
      end
    end

Thor automatically maps commands as such: 

    thor app:install myname --force

That gets converted to:

    App.new.install("myname")
    # with {'force' => true} as options hash

1. Inherit from Thor to turn a class into an option mapper.  
2. Map additional non-valid identifiers to specific methods.  In this case, convert -L to :list
3. Describe the method immediately below.  The first parameter is the usage information, and the second parameter is the description.  
4. Provide any additional options that will be available the instance method options.  

## Types for <tt>method_options</tt>

* :boolean - is parsed as <tt>--option</tt> or <tt>--option=true</tt>
* :string  - is parsed as <tt>--option=VALUE</tt>
* :numeric - is parsed as <tt>--option=N</tt>
* :array   - is parsed as <tt>--option=one two three</tt>
* :hash    - is parsed as <tt>--option=name:string age:integer</tt>

Besides, method_option allows a default value to be given.  Examples:

    method_options :force => false
    #=> Creates a boolean option with default value false

    method_options :alias => "bar"
    #=> Creates a string option with default value "bar"

    method_options :threshold => 3.0
    #=> Creates a numeric option with default value 3.0

You can also supply <tt>:option => :required</tt> to mark an option as required.  The
type is assumed to be string.  If you want a required hash with default values
as option, you can use <tt>method_option</tt> which uses a more declarative style:

    method_option :attributes, :type => :hash, :default => {}, :required => true

All arguments can be set to nil (except required arguments), by suppling a no or
skip variant.  For example: 

    thor app name --no-attributes

In previous versions, aliases for options were created automatically, but now
they should be explicit.  You can supply aliases in both short and declarative
styles:

    method_options %w( force -f ) => :boolean

Or:

    method_option :force, :type => :boolean, :aliases => "-f"

You can supply as many aliases as you want.

NOTE: Type :optional available in Thor 0.9.0 was deprecated. Use :string or :boolean instead.

## Namespaces

By default, your Thor tasks are invoked using Ruby namespace.  In the example
above, tasks are invoked as:

    thor app:install name --force

However, you could namespace your class as:

    module Sinatra
      class App < Thor
        # tasks
      end
    end

And then you should invoke your tasks as:

    thor sinatra:app:install name --force

If desired, you can change the namespace:

    module Sinatra
      class App < Thor
        namespace :myapp
        # tasks
      end
    end

And then your tasks should be invoked as:

    thor myapp:install name --force

## Invocations

Thor comes with a invocation-dependency system as well, which allows a task to be invoked only once.  For example:

    class Counter < Thor
      desc "one", "Prints 1, 2, 3"
      def one
        puts 1
        invoke :two
        invoke :three
      end
      
      desc "two", "Prints 2, 3"
      def two
        puts 2
        invoke :three
      end
      
      desc "three", "Prints 3"
      def three
        puts 3
      end
    end

When invoking the task one:

    thor counter:one

The output is "1 2 3", which means that the three task was invoked only once.  
You can even invoke tasks from another class, so be sure to check the
[documentation](http://rdoc.info/rdoc/wycats/thor/blob/f939a3e8a854616784cac1dcff04ef4f3ee5f7ff/Thor.html).

Notice invocations do not share the same object. I.e, Thor will instantiate Counter once to invoke the task one, then, it instantiates another to invoke the task two and another for task three. This happens to allow options and arguments to parsed again. For example, if two and three have different options and both of them were given to the command line, calling invoke makes them be parsed each time and used accordingly by each task.

## Thor::Group

Thor has a special class called Thor::Group.  The main difference to Thor class
is that it invokes all tasks at once.  The example above could be rewritten in
Thor::Group as this:

    class Counter < Thor::Group
      desc "Prints 1, 2, 3"
      
      def one
        puts 1
      end
     
      def two
        puts 2
      end
      
      def three
        puts 3
      end
    end

When invoked:

    thor counter

It prints "1 2 3" as well.  Notice you should describe (using the method <tt>desc</tt>)
only the class and not each task anymore.  Thor::Group is a great tool to create
generators, since you can define several steps which are invoked in the order they
are defined (Thor::Group is the tool use in generators in Rails 3.0). 

Besides, Thor::Group can parse arguments and options as Thor tasks: 

    class Counter < Thor::Group
      # number will be available as attr_accessor
      argument :number, :type => :numeric, :desc => "The number to start counting"
      desc "Prints the 'number' given upto 'number+2'"
      
      def one
        puts number + 0
      end
      
      def two
        puts number + 1
      end
      
      def three
        puts number + 2
      end
    end

The counter above expects one parameter and has the folling outputs:

    thor counter 5
    # Prints "5 6 7"

    thor counter 11
    # Prints "11 12 13"

You can also give options to Thor::Group, but instead of using <tt>method_option</tt>
and <tt>method_options</tt>, you should use <tt>class_option</tt> and <tt>class_options</tt>.
Both argument and class_options methods are available to Thor class as well.

## Actions

Thor comes with several actions which helps with script and generator tasks.  You
might be familiar with them since some came from Rails Templates.  They are:
<tt>say</tt>, <tt>ask</tt>, <tt>yes?</tt>, <tt>no?</tt>, <tt>add_file</tt>,
<tt>remove_file</tt>, <tt>copy_file</tt>, <tt>template</tt>, <tt>directory</tt>,
<tt>inside</tt>, <tt>run</tt>, <tt>inject_into_file</tt> and a couple more. 

To use them, you just need to include Thor::Actions in your Thor classes:

    class App < Thor
      include Thor::Actions
      # tasks
    end

Some actions like copy file requires that a class method called source_root is
defined in your class.  This is the directory where your templates should be
placed.  Be sure to check the documentation on [actions](http://rdoc.info/rdoc/wycats/thor/blob/f939a3e8a854616784cac1dcff04ef4f3ee5f7ff/Thor/Actions.html).

## Generators

A great use for Thor is creating custom generators.  Combining Thor::Group,
Thor::Actions and ERB templates makes this very easy.  Here is an example:

    class Newgem < Thor::Group
      include Thor::Actions

      # Define arguments and options
      argument :name
      class_option :test_framework, :default => :test_unit

      def self.source_root
        File.dirname(__FILE__)
      end

      def create_lib_file
        template('templates/newgem.tt', "#{name}/lib/#{name}.rb")
      end

      def create_test_file
        test = options[:test_framework] == "rspec" ? :spec : :test
        create_file "#{name}/#{test}/#{name}_#{test}.rb"
      end

      def copy_licence
        if yes?("Use MIT license?")
          # Make a copy of the MITLICENSE file at the source root
          copy_file "MITLICENSE", "#{name}/MITLICENSE"
        else
          say "Shame on you…", :red
        end
      end
    end

Doing a <tt>thor -T</tt> will show how to run our generator.  It should read:
<tt>thor newgem NAME</tt>.  This shows that we have to supply a NAME
argument for our generator to run.

The <tt>create_lib_file</tt> uses an ERB template. This is what it looks like:

    class <%= name.capitalize %>
    end

The arguments that you set in your generator will automatically be passed in
when <tt>template</tt> gets called.  Be sure to read the [documentation](http://rdoc.info/rdoc/wycats/thor/blob/f939a3e8a854616784cac1dcff04ef4f3ee5f7ff/Thor/Actions.html) for
more options.

Running the generator with <tt>thor newgem devise</tt> will
create two files: "devise/lib/devise.rb", and "devise/test/devise_test.rb".  The user will then be asked (via a prompt by the <tt>yes?</tt> method) whether or not they would like to copy the MIT License.  If you want to change the test framework, you can add the option: <tt>thor newgem devise --test-framework=rspec</tt> 

This will generate two files - "devise/lib/devise.rb" and "devise/spec/devise_spec.rb".

## Further Reading

Thor offers many scripting possibilities beyond these examples.  Be sure to read
through the [documentation](http://rdoc.info/rdoc/wycats/thor/blob/f939a3e8a854616784cac1dcff04ef4f3ee5f7ff/Thor.html) and [specs](http://github.com/wycats/thor/tree/master/spec/) to get a better understanding of the options available. 

## License

Released under the MIT License.  See the LICENSE file for further details. 
