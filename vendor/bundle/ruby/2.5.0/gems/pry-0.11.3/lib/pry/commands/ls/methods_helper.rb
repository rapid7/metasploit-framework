require 'pry/commands/ls/jruby_hacks'

module Pry::Command::Ls::MethodsHelper

  include Pry::Command::Ls::JRubyHacks

  private

  # Get all the methods that we'll want to output.
  def all_methods(instance_methods = false)
    methods = if instance_methods || @instance_methods_switch
                Pry::Method.all_from_class(@interrogatee)
              else
                Pry::Method.all_from_obj(@interrogatee)
              end

    if Pry::Helpers::BaseHelpers.jruby? && !@jruby_switch
      methods = trim_jruby_aliases(methods)
    end

    methods.select { |method| @ppp_switch || method.visibility == :public }
  end

  def resolution_order
    if @instance_methods_switch
      Pry::Method.instance_resolution_order(@interrogatee)
    else
      Pry::Method.resolution_order(@interrogatee)
    end
  end

  def format(methods)
    methods.sort_by(&:name).map do |method|
      if method.name == 'method_missing'
        color(:method_missing, 'method_missing')
      elsif method.visibility == :private
        color(:private_method, method.name)
      elsif method.visibility == :protected
        color(:protected_method, method.name)
      else
        color(:public_method, method.name)
      end
    end
  end

end
