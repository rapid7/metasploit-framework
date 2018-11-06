module Pry::Testable::Evalable
  def pry_tester(*args, &block)
    if args.length == 0 || args[0].is_a?(Hash)
      args.unshift(Pry.toplevel_binding)
    end
    Pry::Testable::PryTester.new(*args).tap do |t|
      t.singleton_class.class_eval(&block) if block
    end
  end

  def pry_eval(*eval_strs)
    b = String === eval_strs.first ? Pry.toplevel_binding : Pry.binding_for(eval_strs.shift)
    pry_tester(b).eval(*eval_strs)
  end
end
