class Pry::BasicObject < BasicObject
  [:Kernel, :Pry].each do |constant|
    const_set constant, ::Object.const_get(constant)
  end
  include Kernel
end
