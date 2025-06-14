module Msf::Module::Stability
  extend ActiveSupport::Concern

  module ClassMethods
    def stability
      instance = self.new
      instance.notes['Stability'] || []
    end
  end

  def stability
    self.class.stability
  end

  def stability_to_s
    stability * ', '
  end

end
