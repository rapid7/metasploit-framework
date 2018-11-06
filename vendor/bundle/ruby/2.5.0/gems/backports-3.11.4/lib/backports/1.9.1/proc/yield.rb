require 'backports/tools/alias_method'

Backports.alias_method Proc, :yield, :call
