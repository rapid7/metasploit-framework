module Msf::Module::Reliability
  extend ActiveSupport::Concern

  module ClassMethods
    def reliability
      instance = self.new
      instance.notes['Reliability'] ? instance.notes['Reliability'] : []
    end
  end

  def reliability
    self.class.reliability
  end
end