class Pry
  # @return [Array] Code of the method used when implementing Pry's
  #   __binding__, along with line indication to be used with instance_eval (and
  #   friends).
  #
  # @see Object#__binding__
  BINDING_METHOD_IMPL = [<<-METHOD, __FILE__, __LINE__ + 1]
    # Get a binding with 'self' set to self, and no locals.
    #
    # The default definee is determined by the context in which the
    # definition is eval'd.
    #
    # Please don't call this method directly, see {__binding__}.
    #
    # @return [Binding]
    def __pry__
      binding
    end
  METHOD
end

class Object
  # Start a Pry REPL on self.
  #
  # If `self` is a Binding then that will be used to evaluate expressions;
  # otherwise a new binding will be created.
  #
  # @param [Object] object  the object or binding to pry
  #                         (__deprecated__, use `object.pry`)
  # @param [Hash] hash  the options hash
  # @example With a binding
  #    binding.pry
  # @example On any object
  #   "dummy".pry
  # @example With options
  #   def my_method
  #     binding.pry :quiet => true
  #   end
  #   my_method()
  # @see Pry.start
  def pry(object=nil, hash={})
    if object.nil? || Hash === object
      Pry.start(self, object || {})
    else
      Pry.start(object, hash)
    end
  end

  # Return a binding object for the receiver.
  #
  # The `self` of the binding is set to the current object, and it contains no
  # local variables.
  #
  # The default definee (http://yugui.jp/articles/846) is set such that:
  #
  # * If `self` is a class or module, then new methods created in the binding
  #   will be defined in that class or module (as in `class Foo; end`).
  # * If `self` is a normal object, then new methods created in the binding will
  #   be defined on its singleton class (as in `class << self; end`).
  # * If `self` doesn't have a  real singleton class (i.e. it is a Fixnum, Float,
  #   Symbol, nil, true, or false), then new methods will be created on the
  #   object's class (as in `self.class.class_eval{ }`)
  #
  # Newly created constants, including classes and modules, will also be added
  # to the default definee.
  #
  # @return [Binding]
  def __binding__
    # If you ever feel like changing this method, be careful about variables
    # that you use. They shouldn't be inserted into the binding that will
    # eventually be returned.

    # When you're cd'd into a class, methods you define should be added to it.
    if is_a?(Module)
      # A special case, for JRuby.
      # Module.new.class_eval("binding") has different behaviour than CRuby,
      # where this is not needed: class_eval("binding") vs class_eval{binding}.
      # Using a block works around the difference of behaviour on JRuby.
      # The scope is clear of local variabless. Don't add any.
      #
      # This fixes the following two spec failures, at https://travis-ci.org/pry/pry/jobs/274470002
      # 1) ./spec/pry_spec.rb:360:in `block in (root)'
      # 2) ./spec/pry_spec.rb:366:in `block in (root)'
      return class_eval {binding} if Pry::Helpers::BaseHelpers.jruby? and self.name == nil
      # class_eval sets both self and the default definee to this class.
      return class_eval("binding")
    end

    unless respond_to?(:__pry__)
      # The easiest way to check whether an object has a working singleton class
      # is to try and define a method on it. (just checking for the presence of
      # the singleton class gives false positives for `true` and `false`).
      # __pry__ is just the closest method we have to hand, and using
      # it has the nice property that we can memoize this check.
      begin
        # instance_eval sets the default definee to the object's singleton class
        instance_eval(*Pry::BINDING_METHOD_IMPL)

      # If we can't define methods on the Object's singleton_class. Then we fall
      # back to setting the default definee to be the Object's class. That seems
      # nicer than having a REPL in which you can't define methods.
      rescue TypeError, Pry::FrozenObjectException
        # class_eval sets the default definee to self.class
        self.class.class_eval(*Pry::BINDING_METHOD_IMPL)
      end
    end

    __pry__
  end
end

class BasicObject
  # Return a binding object for the receiver.
  #
  # The `self` of the binding is set to the current object, and it contains no
  # local variables.
  #
  # The default definee (http://yugui.jp/articles/846) is set such that new
  # methods defined will be added to the singleton class of the BasicObject.
  #
  # @return [Binding]
  def __binding__
    # BasicObjects don't have respond_to?, so we just define the method
    # every time. As they also don't have `.freeze`, this call won't
    # fail as it can for normal Objects.
    (class << self; self; end).class_eval <<-EOF, __FILE__, __LINE__ + 1
      # Get a binding with 'self' set to self, and no locals.
      #
      # The default definee is determined by the context in which the
      # definition is eval'd.
      #
      # Please don't call this method directly, see {__binding__}.
      #
      # @return [Binding]
      def __pry__
        ::Kernel.binding
      end
    EOF
    self.__pry__
  end
end
