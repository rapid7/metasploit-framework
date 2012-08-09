class Spork::RunStrategy
  attr_reader :test_framework
  @@run_strategies = []

  def initialize(test_framework)
    @test_framework = test_framework
  end

  def preload
    raise NotImplementedError
  end

  def run(argv, input, output)
    raise NotImplementedError
  end

  def cleanup
    raise NotImplementedError
  end

  def running?
    raise NotImplementedError
  end

  def assert_ready!
    raise NotImplementedError
  end

  def abort
    raise NotImplementedError
  end

  protected
    def self.factory(test_framework)
      if RUBY_PLATFORM =~ /mswin|mingw|java/
        Spork::RunStrategy::Magazine.new(test_framework)
      else
        Spork::RunStrategy::Forking.new(test_framework)
      end
    end

    def self.inherited(subclass)
      @@run_strategies << subclass
    end

end

Dir[File.dirname(__FILE__) + "/run_strategy/*.rb"].each { |file| require file }
