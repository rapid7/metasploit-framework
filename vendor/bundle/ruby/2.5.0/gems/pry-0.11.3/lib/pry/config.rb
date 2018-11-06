require_relative 'basic_object'
class Pry::Config < Pry::BasicObject
  require_relative 'config/behavior'
  require_relative 'config/memoization'
  require_relative 'config/default'
  require_relative 'config/convenience'
  include Pry::Config::Behavior
  def self.shortcuts
    Convenience::SHORTCUTS
  end
end
