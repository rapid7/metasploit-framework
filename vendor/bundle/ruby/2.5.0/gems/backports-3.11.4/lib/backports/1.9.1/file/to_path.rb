require 'backports/tools/alias_method'

Backports.alias_method File, :to_path, :path
