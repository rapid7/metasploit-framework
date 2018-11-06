require 'backports/tools/alias_method'

Backports.alias_method String, :setbyte, :[]=
