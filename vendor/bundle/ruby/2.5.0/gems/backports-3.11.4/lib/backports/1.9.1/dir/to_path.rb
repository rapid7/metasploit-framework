require 'backports/tools/alias_method'

Backports.alias_method Dir, :to_path, :path
