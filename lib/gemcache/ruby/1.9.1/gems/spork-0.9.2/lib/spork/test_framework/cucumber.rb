class Spork::TestFramework::Cucumber < Spork::TestFramework
  DEFAULT_PORT = 8990
  HELPER_FILE = File.join(Dir.pwd, "features/support/env.rb")

  class << self
    # REMOVE WHEN SUPPORT FOR 0.3.95 AND EARLIER IS DROPPED
    attr_accessor :mother_object
  end

  def preload
    require 'cucumber'
    if ::Cucumber::VERSION >= '0.9.0' && ::Cucumber::VERSION < '1.0.0'
      # nothing to do nowadays
    else
      preload_legacy_cucumbers
    end
    super
  end

  def run_tests(argv, stderr, stdout)
    if ::Cucumber::VERSION >= '0.9.0'  && ::Cucumber::VERSION < '1.0.0'
      ::Cucumber::Cli::Main.new(argv, stdout, stderr).execute!
    else
      ::Cucumber::Cli::Main.new(argv, stdout, stderr).execute!(@step_mother)
    end
  end

  private
  
  def preload_legacy_cucumbers
    begin
      @step_mother = ::Cucumber::Runtime.new
      @step_mother.load_programming_language('rb')
    rescue NoMethodError => pre_cucumber_0_4 # REMOVE WHEN SUPPORT FOR PRE-0.4 IS DROPPED
      @step_mother = Spork::Server::Cucumber.mother_object
    end
  end
end
