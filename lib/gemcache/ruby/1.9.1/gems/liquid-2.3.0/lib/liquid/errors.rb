module Liquid
  class Error < ::StandardError; end
  
  class ArgumentError < Error; end
  class ContextError < Error; end
  class FilterNotFound < Error; end
  class FileSystemError < Error; end
  class StandardError < Error; end
  class SyntaxError < Error; end
  class StackLevelError < Error; end
end