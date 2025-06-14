module Msf::Module::Reliability
  extend ActiveSupport::Concern

  module ClassMethods
    def reliability
      instance = self.new
      instance.notes['Reliability'] || []
    end
  end

  def reliability
    self.class.reliability
  end

  def reliability_to_s
    reliability * ', '
  end
end