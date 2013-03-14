require 'windows/api'

module Windows
  module COM
    module Accessibility
      API.auto_namespace = 'Windows::COM::Accessibility'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private
         
      API.new('ObjectFromLresult', 'LPIP', 'L', 'oleacc')
    end
  end
end
