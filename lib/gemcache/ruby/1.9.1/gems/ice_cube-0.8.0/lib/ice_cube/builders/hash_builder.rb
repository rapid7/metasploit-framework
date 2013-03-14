module IceCube

  class HashBuilder
  
    def initialize(rule = nil)
      @hash = { :validations => {}, :rule_type => rule.class.name }
    end

    def validations
      @hash[:validations]
    end

    def []=(key, value)
      @hash[key] = value
    end

    def validations_array(type)
      validations[type] ||= []
    end

    def to_hash
      @hash
    end

  end

end
