# good idea ???
# if you're testing pry plugin you should require pry by yourself, no?
require 'pry' if not defined?(Pry)

module Pry::Testable
  extend self
  require_relative "testable/pry_tester"
  require_relative "testable/evalable"
  require_relative "testable/mockable"
  require_relative "testable/variables"
  require_relative "testable/utility"

  #
  # When {Pry::Testable} is included into another module or class,
  # the following modules are also included: {Pry::Testable::Mockable},
  # {Pry::Testable::Evalable}, {Pry::Testable::Variables}, and
  # {Pry::Testable::Utility}.
  #
  # @note
  #   Each of the included modules mentioned above may also be used
  #   standalone or in a pick-and-mix fashion.
  #
  # @param [Module] mod
  #   A class or module.
  #
  # @return [void]
  #
  def self.included(mod)
    mod.module_eval do
      include Pry::Testable::Mockable
      include Pry::Testable::Evalable
      include Pry::Testable::Variables
      include Pry::Testable::Utility
    end
  end

  TEST_DEFAULTS = {
    color: false,
    pager: false,
    should_load_rc: false,
    should_load_local_rc: false,
    correct_indent: false,
    collison_warning: false,
    history: {
      should_load: false,
      should_save: false
    }
  }
  private_constant :TEST_DEFAULTS

  #
  # Sets various configuration options that make Pry optimal for a test
  # environment, see source code for complete details.
  #
  # @return [void]
  #
  def self.set_testenv_variables
    Pry.config = Pry::Config.from_hash(TEST_DEFAULTS, Pry::Config::Default.new)
    Pry.config.hooks = Pry::Hooks.new
  end

  #
  # Reset the Pry configuration to their default values.
  #
  # @return [void]
  #
  def self.unset_testenv_variables
    Pry.config = Pry::Config.from_hash({}, Pry::Config::Default.new)
  end
end
