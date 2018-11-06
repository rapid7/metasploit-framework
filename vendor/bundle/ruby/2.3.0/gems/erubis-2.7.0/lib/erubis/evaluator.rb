##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/error'
require 'erubis/context'


module Erubis

  EMPTY_BINDING = binding()


  ##
  ## evaluate code
  ##
  module Evaluator

    def self.supported_properties    # :nodoc:
      return []
    end

    attr_accessor :src, :filename

    def init_evaluator(properties)
      @filename = properties[:filename]
    end

    def result(*args)
      raise NotSupportedError.new("evaluation of code except Ruby is not supported.")
    end

    def evaluate(*args)
      raise NotSupportedError.new("evaluation of code except Ruby is not supported.")
    end

  end


  ##
  ## evaluator for Ruby
  ##
  module RubyEvaluator
    include Evaluator

    def self.supported_properties    # :nodoc:
      list = Evaluator.supported_properties
      return list
    end

    ## eval(@src) with binding object
    def result(_binding_or_hash=TOPLEVEL_BINDING)
      _arg = _binding_or_hash
      if _arg.is_a?(Hash)
        _b = binding()
        eval _arg.collect{|k,v| "#{k} = _arg[#{k.inspect}]; "}.join, _b
      elsif _arg.is_a?(Binding)
        _b = _arg
      elsif _arg.nil?
        _b = binding()
      else
        raise ArgumentError.new("#{self.class.name}#result(): argument should be Binding or Hash but passed #{_arg.class.name} object.")
      end
      return eval(@src, _b, (@filename || '(erubis'))
    end

    ## invoke context.instance_eval(@src)
    def evaluate(_context=Context.new)
      _context = Context.new(_context) if _context.is_a?(Hash)
      #return _context.instance_eval(@src, @filename || '(erubis)')
      #@_proc ||= eval("proc { #{@src} }", Erubis::EMPTY_BINDING, @filename || '(erubis)')
      @_proc ||= eval("proc { #{@src} }", binding(), @filename || '(erubis)')
      return _context.instance_eval(&@_proc)
    end

    ## if object is an Class or Module then define instance method to it,
    ## else define singleton method to it.
    def def_method(object, method_name, filename=nil)
      m = object.is_a?(Module) ? :module_eval : :instance_eval
      object.__send__(m, "def #{method_name}; #{@src}; end", filename || @filename || '(erubis)')
    end


  end


end
