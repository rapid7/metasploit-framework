# Note: Must be required explicitely!
# This is a best attempt to fake BasicObject in Ruby 1.8.x
# What you do get:
#  * as few methods as the real BasicObject (at the moment the library is required...)
#  * BasicObject === <anything> # ==> returns true
# What you don't get:
#  * BasicObject is not in the ancestor list of all classes and thus
#  * Comparisons between classes won't work, e.g.
#      Object < BasicObject # ==> returns true instead of false
#  * Instance methods added to Object or Kernel after you require 'backports/basic_object'
#    might also be available in instances of BasicObject and subclasses
#    (they will only be undefined whenever a subclass of BasicObject is created)
# Because of all the fineprint, BasicObject must be required explicitely

unless Object.const_defined? :BasicObject

  class BasicObject
    KEEP = %w[== equal? ! != instance_eval instance_exec __send__]
    KEEP.concat KEEP.map { |e| e.to_sym }

    # undefine almost all instance methods
    begin
      old_verbose, $VERBOSE = $VERBOSE, nil # silence the warning for undefining __id__
      (instance_methods - KEEP).each do |method|
        undef_method method
      end
    ensure
      $VERBOSE = old_verbose
    end

    class << self
      def === (cmp)
        true
      end

      # Let's try to keep things clean, in case methods have been added to Object
      # either directly or through an included module.
      # We'll do this whenever a class is derived from BasicObject
      # Ideally, we'd do this by trapping Object.method_added
      # and M.method_added for any module M included in Object or a submodule
      # Seems really though to get right, but pull requests welcome ;-)
      def inherited(sub)
        BasicObject.class_eval do
          (instance_methods - KEEP).each do |method|
            if Object.method_defined?(method) && instance_method(method).owner == Object.instance_method(method).owner
              undef_method method
            end
          end
        end
      end
    end
  end
end
