require 'backports/tools/alias_method_chain'
class Hash
  if {}.select{} == []
    def select_with_hash_return
      return to_enum(:select) unless block_given?
      Hash[select_without_hash_return{|k, v| yield [k, v]}]
    end
    Backports.alias_method_chain self, :select, :hash_return
  end
end
