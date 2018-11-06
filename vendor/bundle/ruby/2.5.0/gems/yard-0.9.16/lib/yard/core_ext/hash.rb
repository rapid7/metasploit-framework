# frozen_string_literal: true
class Hash
  class << self
    def create(*args)
      if args.first.is_a?(Array) && args.size == 1
        obj = new
        args.first.each {|k, v| obj[k] = v }
        obj
      else
        create_186(*args)
      end
    end
    alias create_186 []
    alias [] create
  end
end if RUBY_VERSION < "1.8.7"
