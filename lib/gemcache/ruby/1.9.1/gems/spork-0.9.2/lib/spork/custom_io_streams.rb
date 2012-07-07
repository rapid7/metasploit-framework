# This class is mainly used for testing.
# When included (and used), it gives us an opportunity to stub out the output streams used for a given class
module Spork::CustomIOStreams
  def self.included(klass)
    klass.send(:extend, ::Spork::CustomIOStreams::ClassMethods)
  end
  
  def stderr
    self.class.stderr
  end

  def stdout
    self.class.stdout
  end
  
  module ClassMethods
    def stderr
      $stderr
    end
  
    def stdout
      $stdout
    end
  end
end