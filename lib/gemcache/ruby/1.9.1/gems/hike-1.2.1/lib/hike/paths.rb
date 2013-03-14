require 'pathname'
require 'hike/normalized_array'

module Hike
  # `Paths` is an internal collection for tracking path strings.
  class Paths < NormalizedArray
    def initialize(root = ".")
      @root = Pathname.new(root)
      super()
    end

    # Relative paths added to this array are expanded relative to `@root`.
    #
    #     paths = Paths.new("/usr/local")
    #     paths << "tmp"
    #     paths << "/tmp"
    #
    #     paths
    #     # => ["/usr/local/tmp", "/tmp"]
    #
    def normalize_element(path)
      path = Pathname.new(path)
      path = @root.join(path) if path.relative?
      path.expand_path.to_s
    end
  end
end
