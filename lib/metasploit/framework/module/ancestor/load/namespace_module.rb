# ensure the namespace modules parent module is defined without any namespace module being defined.
require 'msf/core/modules'

# Concerns namespace that wraps the ruby `Module` in `Metasploit::Model::Module::Ancestor#contents`
module Metasploit::Framework::Module::Ancestor::Load::NamespaceModule
  #
  # CONSTANTS
  #

  # Path for {NAMESPACE_MODULE_CONTENT} evaluation so that errors are reported correctly.
  NAMESPACE_MODULE_FILE = __FILE__
  # This must calculate the first line of the NAMESPACE_MODULE_CONTENT string so that errors are reported correctly
  NAMESPACE_MODULE_LINE = __LINE__ + 4
  # By calling module_eval inside of module_eval_with_lexical_scope in the namespace module's body, the lexical scope
  # is captured and available to the code passed to module_eval_with_lexical_scope.
  NAMESPACE_MODULE_CONTENT = <<-EOS
    # ensure the namespace module can respond to checks during loading
    extend Metasploit::Framework::Module::Ancestor::Namespace

    # Calls `Module#module_eval` on the `module_ancestor_contents`, but the lexical scope of the namespace_module is
    # passed through module_eval, so that `module_ancestor_contents` can act like it was written inline in the
    # namespace_module.
    #
    # @param module_ancestor_contents [String] `Metasploit::Model::Module::Ancestor#contents`
    # @param module_ancestor_real_path [String] The path to the `Module`, so that error messages in evaluating
    #   `module_ancestor_contents` can be reported correctly.
    def self.module_eval_with_lexical_scope(module_ancestor_contents, module_ancestor_real_path)
      # By calling module_eval from inside the module definition, the lexical scope is captured and available to the
      # code in `module_ancestor_contents`.
      module_eval(module_ancestor_contents, module_ancestor_real_path)
    end
  EOS
  # The base namespace name under which {#create_namespace_module namespace modules are created}.
  NAMESPACE_MODULE_NAMES = ['Msf', 'Modules']

  #
  # Methods
  #

  # Returns an Array of names to make a fully qualified module name to wrap the Metasploit<n> class so that it
  # doesn't overwrite other (metasploit) module's `Modules`.
  #
  # @param module_ancestor [Metasploit::Model::Module::Ancestor] The `Metasploit::Model::Module::Ancestor` whose
  #   `Metasploit::Model::Module::Ancestor#contents` will be evaluated inside the nested `module` declarations of
  #   this array of `Module#name`s.
  # @return [Array<String>] {NAMESPACE_MODULE_NAMES} + <derived-constant-safe names>
  #
  # @see namespace_module
  def namespace_module_names(module_ancestor)
    NAMESPACE_MODULE_NAMES + ["RealPathSha1HexDigest#{module_ancestor.real_path_sha1_hex_digest}"]
  end

  private

  # Returns a nested `Module` to wrap the Metasploit<n> `Module` so that it doesn't overwrite other (metasploit)
  # module's `Module`s.  The wrapper `Module` must be named so that active_support's autoloading code doesn't break when
  # searching constants from inside the `Metasploit<n>` `Module`.
  #
  # @param namespace_module_names [Array<String>] {#namespace_module_names}
  # @return [Module, #module_eval_with_lexical_scope] `Module` that can wrap
  #   `Metasploit::Model::Module::Ancestor#contents` using `#module_eval_with_lexical_scope`.
  #
  # @see NAMESPACE_MODULE_CONTENT
  def create_namespace_module(namespace_module_names)
    # In order to have constants defined in {Msf} resolve without the {Msf} qualifier in the module_content, the
    # Module.nesting must resolve for the entire nesting.  Module.nesting is strictly lexical, and can't be faked with
    # module_eval(&block). (There's actually code in ruby's implementation to stop module_eval from being added to
    # Module.nesting when using the block syntax.) All this means is the modules have to be declared as a string that
    # gets module_eval'd.

    nested_module_names = namespace_module_names.reverse

    namespace_module_content = nested_module_names.inject(NAMESPACE_MODULE_CONTENT) { |wrapped_content, module_name|
      lines = []
      lines << "module #{module_name}"
      lines << wrapped_content
      lines << "end"

      lines.join("\n")
    }

    # - because the added wrap lines have to act like they were written before NAMESPACE_MODULE_CONTENT
    line_with_wrapping = NAMESPACE_MODULE_LINE - nested_module_names.length
    Object.module_eval(namespace_module_content, NAMESPACE_MODULE_FILE, line_with_wrapping)

    # The namespace_module exists now, so no need to use constantize to do const_missing
    namespace_module = current_module(namespace_module_names)

    namespace_module
  end

  # Returns the module with `module_names` if it exists.
  #
  # @param [Array<String>] module_names a list of module names to resolve from Object downward.
  # @return [Module] module that wraps the previously loaded content from {#read_module_content}.
  # @return [nil] if any module name along the chain does not exist.
  def current_module(module_names)
    # dont' look at ancestor for constant for faster const_defined? calls.
    inherit = false

    # Don't want to trigger ActiveSupport's const_missing, so can't use constantize.
    named_module = module_names.inject(Object) { |parent, module_name|
      if parent.const_defined?(module_name, inherit)
        parent.const_get(module_name)
      else
        break
      end
    }

    named_module
  end

  # Creates a new namespace `Module` for `module_ancestor`'s `Metasploit::Model::Module::Ancestor#contents` to be
  # evaluated within.  If there was a previous module with the same name, then it is moved aside and restored if
  # the `Metasploit::Model::Module::Ancestor#contents` are invalid.
  #
  # @example Load `Metasploit::Model::Module::Ancestor#contents` without error handling
  #   namespace_module_transaction(module_ancestor) do |
  #
  # @param module_ancestor [Metasploit::Model::Module::Ancestor]
  # @yield [module_ancestor, namespace_module]
  # @yieldparam module_ancestor [Metasploit::Model::Module::Ancestor] `module_ancestor` argument to method.  Passed to
  #   block so that block can be a method reference like `&:method`.
  # @yieldparam namespace_module [Module, #module_eval_with_lexical_scope] Module in which to evaluate
  #   [Metasploit::Model::Module::Ancestor#contents]
  # @yieldreturn [true] to keep new namespace module.
  # @yieldreturn [false] to restore old namespace module.
  # @return [Boolean] yield return.
  def namespace_module_transaction(module_ancestor, &block)
    namespace_module_names = self.namespace_module_names(module_ancestor)

    previous_namespace_module = current_module(namespace_module_names)
    relative_name = namespace_module_names.last

    if previous_namespace_module
      parent_module = previous_namespace_module.parent
      # remove_const is private, so use send to bypass
      parent_module.send(:remove_const, relative_name)
    end

    namespace_module = create_namespace_module(namespace_module_names)
    # Get the parent module from the created module so that
    # restore_namespace_module can remove namespace_module's constant if
    # needed.
    parent_module = namespace_module.parent

    begin
      commit = block.call(module_ancestor, namespace_module)
    rescue Exception
      restore_namespace_module(parent_module, relative_name, previous_namespace_module)

      # re-raise the original exception in the original context
      raise
    else
      unless commit
        restore_namespace_module(parent_module, relative_name, previous_namespace_module)
      end

      commit
    end
  end

  # Restores the namespace `Module` to it's original name under it's original parent `Module` if there was a previous
  # namespace `Module`.
  #
  # @param parent_module [Module] The `#parent` of `namespace_module` before it was removed from the constant tree.
  # @param relative_name [String] The name of the constant under `parent_module` where `namespace_module` was attached.
  # @param namespace_module [Module, nil] The previous namespace `Module` containing the old `Module` content.  If
  #   `nil`, then the `relative_name` constant is removed from `parent_module`, but nothing is set as the new constant.
  # @return [void]
  def restore_namespace_module(parent_module, relative_name, namespace_module)
    if parent_module
      inherit = false

      # If there is a current module with relative_name
      if parent_module.const_defined?(relative_name, inherit)
        # if the current value isn't the value to be restored.
        if parent_module.const_get(relative_name, inherit) != namespace_module
          # remove_const is private, so use send to bypass
          parent_module.send(:remove_const, relative_name)

          # if there was a previous module, not set it to the name
          if namespace_module
            parent_module.const_set(relative_name, namespace_module)
          end
        end
      else
        # if there was a previous module, but there isn't a current module, then restore the previous module
        if namespace_module
          parent_module.const_set(relative_name, namespace_module)
        end
      end
    end
  end
end