# Namespace for all models dealing with module caching.
module Mdm::Module
  extend ActiveSupport::Autoload

  autoload :Action
  autoload :Arch
  autoload :Author
  autoload :Detail
  autoload :Mixin
  autoload :Platform
  autoload :Ref
  autoload :Target
end