require 'windows/api'

module Windows
  module COM
    module Variant
      API.auto_namespace = 'Windows::COM::Variant'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private
         
      VARIANT_TRUE  = -1
      VARIANT_FALSE = 0
        
      API.new('VariantChangeType', 'PPIL', 'L', 'oleaut32')
      API.new('VariantChangeTypeEx', 'PPLLL', 'L', 'oleaut32')
      API.new('VariantClear', 'P', 'L', 'oleaut32')       
      API.new('VariantCopy', 'PP', 'L', 'oleaut32')       
      API.new('VariantCopyInd', 'PP', 'L', 'oleaut32')       
      API.new('VariantInit', 'P', 'V', 'oleaut32')       
    end      
  end   
end
