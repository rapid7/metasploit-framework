# encoding: utf-8

# This is not loaded if ActiveSupport is already loaded

class Object
  def blank?
    if respond_to?(:empty?)
      empty?
    else
     !self
    end
  end
end
