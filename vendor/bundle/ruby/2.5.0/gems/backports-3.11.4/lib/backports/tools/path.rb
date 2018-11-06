require 'backports/tools/alias_method_chain'
require 'backports/tools/arguments'

module Backports
  # Metaprogramming utility to convert the first file argument to path
  def self.convert_first_argument_to_path(klass, selector)
    mod = class << klass; self; end
    unless mod.method_defined? selector
      warn "#{mod}##{selector} is not defined, so argument can't converted to path"
      return
    end
    arity = mod.instance_method(selector).arity
    last_arg = []
    if arity < 0
      last_arg = ["*rest"]
      arity = -1-arity
    end
    arg_sequence = (["file"] + (1...arity).map{|i| "arg_#{i}"} + last_arg + ["&block"]).join(", ")

    alias_method_chain(mod, selector, :potential_path_argument) do |aliased_target, punctuation|
      mod.module_eval <<-end_eval, __FILE__, __LINE__ + 1
        def #{aliased_target}_with_potential_path_argument#{punctuation}(#{arg_sequence})
          file = Backports.convert_path(file)
          #{aliased_target}_without_potential_path_argument#{punctuation}(#{arg_sequence})
        end
      end_eval
    end
  end

  # Metaprogramming utility to convert all file arguments to paths
  def self.convert_all_arguments_to_path(klass, selector, skip)
    mod = class << klass; self; end
    unless mod.method_defined? selector
      warn "#{mod}##{selector} is not defined, so arguments can't converted to path"
      return
    end
    first_args = (1..skip).map{|i| "arg_#{i}"}.join(",") + (skip > 0 ? "," : "")
    alias_method_chain(mod, selector, :potential_path_arguments) do |aliased_target, punctuation|
      mod.module_eval <<-end_eval, __FILE__, __LINE__ + 1
        def #{aliased_target}_with_potential_path_arguments#{punctuation}(#{first_args}*files, &block)
          files = files.map{|f| Backports.convert_path(f) }
          #{aliased_target}_without_potential_path_arguments#{punctuation}(#{first_args}*files, &block)
        end
      end_eval
    end
  end

  def self.convert_path(path)
    try_convert(path, IO, :to_io) ||
    begin
      path = path.to_path if path.respond_to?(:to_path)
      try_convert(path, String, :to_str) || path
    end
  end
end
