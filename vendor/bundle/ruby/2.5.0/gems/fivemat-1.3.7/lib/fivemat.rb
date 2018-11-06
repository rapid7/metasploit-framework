require 'fivemat/elapsed_time'

module Fivemat
  autoload :Cucumber, 'fivemat/cucumber'
  autoload :Cucumber3, 'fivemat/cucumber3'
  autoload :MiniTest, 'fivemat/minitest/unit'
  autoload :RSpec, 'fivemat/rspec'
  autoload :RSpec3, 'fivemat/rspec3'
  autoload :Spec, 'fivemat/spec'

  def cucumber3?
    defined?(::Cucumber) && ::Cucumber::VERSION >= '3'
  end
  module_function :cucumber3?

  # Cucumber detects the formatter API based on initialize arity
  if cucumber3?
    def initialize(config)
    end
  else
    def initialize(runtime, path_or_io, options)
    end
  end

  def rspec3?
    defined?(::RSpec::Core) && ::RSpec::Core::Version::STRING >= '3.0.0'
  end
  module_function :rspec3?

  if rspec3?
    # This needs to be run before `.new` is called, so putting it inside the
    # autoloaded rspec3 file will not work.
    ::RSpec::Core::Formatters.register self,
      :example_passed,
      :example_pending,
      :example_failed,
      :example_group_started,
      :example_group_finished,
      :dump_summary,
      :seed,
      :message
  end

  def self.new(*args)
    case args.size
    when 0 then MiniTest::Unit
    when 1 then
      if args.first.class.to_s == "Cucumber::Configuration"
        Cucumber3
      elsif rspec3?
        RSpec3
      else
        RSpec
      end
    when 2 then Spec
    when 3
      Cucumber
    else
      raise ArgumentError
    end.new(*args)
  end
end
