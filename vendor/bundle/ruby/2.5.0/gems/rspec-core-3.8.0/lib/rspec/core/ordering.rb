module RSpec
  module Core
    # @private
    module Ordering
      # @private
      # The default global ordering (defined order).
      class Identity
        def order(items)
          items
        end
      end

      # @private
      # Orders items randomly.
      class Random
        def initialize(configuration)
          @configuration = configuration
          @used = false
        end

        def used?
          @used
        end

        def order(items)
          @used = true

          seed = @configuration.seed.to_s
          items.sort_by { |item| jenkins_hash_digest(seed + item.id) }
        end

      private

        # http://en.wikipedia.org/wiki/Jenkins_hash_function
        # Jenkins provides a good distribution and is simpler than MD5.
        # It's a bit slower than MD5 (primarily because `Digest::MD5` is
        # implemented in C) but has the advantage of not requiring us
        # to load another part of stdlib, which we try to minimize.
        def jenkins_hash_digest(string)
          hash = 0

          string.each_byte do |byte|
            hash += byte
            hash &= MAX_32_BIT
            hash += ((hash << 10) & MAX_32_BIT)
            hash &= MAX_32_BIT
            hash ^= hash >> 6
          end

          hash += ((hash << 3) & MAX_32_BIT)
          hash &= MAX_32_BIT
          hash ^= hash >> 11
          hash += ((hash << 15) & MAX_32_BIT)
          hash &= MAX_32_BIT
          hash
        end

        MAX_32_BIT = 4_294_967_295
      end

      # @private
      # Orders items based on a custom block.
      class Custom
        def initialize(callable)
          @callable = callable
        end

        def order(list)
          @callable.call(list)
        end
      end

      # @private
      # Stores the different ordering strategies.
      class Registry
        def initialize(configuration)
          @configuration = configuration
          @strategies    = {}

          register(:random,  Random.new(configuration))

          identity = Identity.new
          register(:defined, identity)

          # The default global ordering is --defined.
          register(:global, identity)
        end

        def fetch(name, &fallback)
          @strategies.fetch(name, &fallback)
        end

        def register(sym, strategy)
          @strategies[sym] = strategy
        end

        def used_random_seed?
          @strategies[:random].used?
        end
      end

      # @private
      # Manages ordering configuration.
      #
      # @note This is not intended to be used externally. Use
      #       the APIs provided by `RSpec::Core::Configuration` instead.
      class ConfigurationManager
        attr_reader :seed, :ordering_registry

        def initialize
          @ordering_registry = Registry.new(self)
          @seed = rand(0xFFFF)
          @seed_forced = false
          @order_forced = false
        end

        def seed_used?
          ordering_registry.used_random_seed?
        end

        def seed=(seed)
          return if @seed_forced
          register_ordering(:global, ordering_registry.fetch(:random))
          @seed = seed.to_i
        end

        def order=(type)
          order, seed = type.to_s.split(':')
          @seed = seed.to_i if seed

          ordering_name = if order.include?('rand')
                            :random
                          elsif order == 'defined'
                            :defined
                          end

          register_ordering(:global, ordering_registry.fetch(ordering_name)) if ordering_name
        end

        def force(hash)
          if hash.key?(:seed)
            self.seed = hash[:seed]
            @seed_forced  = true
            @order_forced = true
          elsif hash.key?(:order)
            self.order = hash[:order]
            @order_forced = true
          end
        end

        def register_ordering(name, strategy=Custom.new(Proc.new { |l| yield l }))
          return if @order_forced && name == :global
          ordering_registry.register(name, strategy)
        end
      end
    end
  end
end
