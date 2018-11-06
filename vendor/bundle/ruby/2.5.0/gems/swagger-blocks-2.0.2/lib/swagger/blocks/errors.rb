module Swagger
  module Blocks
    class Error < StandardError; end
    class DeclarationError < Error; end
    class NotFoundError < Error; end
    class NotSupportedError < Error; end
  end
end
