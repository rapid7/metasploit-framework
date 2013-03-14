require 'hike/normalized_array'

module Hike
  # `Extensions` is an internal collection for tracking extension names.
  class Extensions < NormalizedArray
    # Extensions added to this array are normalized with a leading
    # `.`.
    #
    #     extensions << "js"
    #     extensions << ".css"
    #
    #     extensions
    #     # => [".js", ".css"]
    #
    def normalize_element(extension)
      if extension[/^\./]
        extension
      else
        ".#{extension}"
      end
    end
  end
end
