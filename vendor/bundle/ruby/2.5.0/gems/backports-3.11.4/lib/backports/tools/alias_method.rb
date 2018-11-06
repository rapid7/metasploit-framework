module Backports
  # Safe alias_method that will only alias if the source exists and destination doesn't
  def self.alias_method(mod, new_name, old_name)
    mod.instance_eval do
      alias_method new_name, old_name
    end if mod.method_defined?(old_name) && !mod.method_defined?(new_name)
  end
end
