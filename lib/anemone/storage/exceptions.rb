module Anemone
  module Storage

    class GenericError < Error; end;

    class ConnectionError < Error; end

    class RetrievalError < Error; end

    class InsertionError < Error; end

    class CloseError < Error; end

  end
end
