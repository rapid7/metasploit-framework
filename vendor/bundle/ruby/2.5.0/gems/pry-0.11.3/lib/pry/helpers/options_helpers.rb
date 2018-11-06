class Pry
  module Helpers
    module OptionsHelpers
      module_function

      # Add method options to the Pry::Slop instance
      def method_options(opt)
        @method_target = target
        opt.on :M, "instance-methods", "Operate on instance methods."
        opt.on :m, :methods, "Operate on methods."
        opt.on :s, :super, "Select the 'super' method. Can be repeated to traverse the ancestors.", :as => :count
        opt.on :c, :context, "Select object context to run under.", :argument => true do |context|
          @method_target = Pry.binding_for(target.eval(context))
        end
      end

      # Get the method object parsed by the slop instance
      def method_object
        @method_object ||= get_method_or_raise(args.empty? ? nil : args.join(" "), @method_target,
                            :super => opts[:super],
                            :instance => opts.present?(:'instance-methods') && !opts.present?(:'methods'),
                            :methods  => opts.present?(:'methods') && !opts.present?(:'instance-methods')
                           )
      end
    end
  end
end
