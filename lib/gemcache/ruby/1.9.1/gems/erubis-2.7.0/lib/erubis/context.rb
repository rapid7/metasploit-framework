##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##


module Erubis


  ##
  ## context object for Engine#evaluate
  ##
  ## ex.
  ##   template = <<'END'
  ##   Hello <%= @user %>!
  ##   <% for item in @list %>
  ##    - <%= item %>
  ##   <% end %>
  ##   END
  ##
  ##   context = Erubis::Context.new(:user=>'World', :list=>['a','b','c'])
  ##   # or
  ##   # context = Erubis::Context.new
  ##   # context[:user] = 'World'
  ##   # context[:list] = ['a', 'b', 'c']
  ##
  ##   eruby = Erubis::Eruby.new(template)
  ##   print eruby.evaluate(context)
  ##
  class Context
    include Enumerable

    def initialize(hash=nil)
      hash.each do |name, value|
        self[name] = value
      end if hash
    end

    def [](key)
      return instance_variable_get("@#{key}")
    end

    def []=(key, value)
      return instance_variable_set("@#{key}", value)
    end

    def keys
      return instance_variables.collect { |name| name[1..-1] }
    end

    def each
      instance_variables.each do |name|
        key = name[1..-1]
        value = instance_variable_get(name)
        yield(key, value)
      end
    end

    def to_hash
      hash = {}
      self.keys.each { |key| hash[key] = self[key] }
      return hash
    end

    def update(context_or_hash)
      arg = context_or_hash
      if arg.is_a?(Hash)
        arg.each do |key, val|
          self[key] = val
        end
      else
        arg.instance_variables.each do |varname|
          key = varname[1..-1]
          val = arg.instance_variable_get(varname)
          self[key] = val
        end
      end
    end

  end


end
