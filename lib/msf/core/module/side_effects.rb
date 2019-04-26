module Msf::Module::SideEffects
  extend ActiveSupport::Concern

  module ClassMethods
    def side_effects
      instance = self.new
      instance.notes['SideEffects'] || []
    end
  end

  def side_effects
    self.class.side_effects
  end

  def side_effects_to_s
    side_effects * ', '
  end
end
