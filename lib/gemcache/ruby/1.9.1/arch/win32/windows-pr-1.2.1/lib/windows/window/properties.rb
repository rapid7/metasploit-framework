require 'windows/api'

module Windows
  module Window
    module Properties
      API.auto_namespace = 'Windows::Window::Properties'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      API.new('EnumProps', 'LK', 'I', 'user32')
      API.new('EnumPropsEx', 'LKL', 'I', 'user32')
      API.new('GetProp', 'LP', 'L', 'user32')
      API.new('RemoveProp', 'LP', 'L', 'user32')
      API.new('SetProp', 'LPL', 'B', 'user32')
    end
  end
end
