require 'backports/tools/alias_method'
require 'backports/1.9.1/enumerable/each_with_object'

Enumerator = Enumerable::Enumerator unless Object.const_defined? :Enumerator # Standard in ruby 1.9

Backports.alias_method Enumerator, :with_object, :each_with_object
