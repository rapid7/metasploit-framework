module Faker
  class University < Base
    flexible :university

    class << self
      def name
        parse('university.name')
      end

      def prefix
        fetch('university.prefix')
      end

      def suffix
        fetch('university.suffix')
      end

      def greek_organization
        Array.new(3) { |_| sample(greek_alphabet) }.join
      end

      def greek_alphabet
        %w[Α B Γ Δ E Z H Θ I K Λ M N Ξ
           O Π P Σ T Y Φ X Ψ Ω]
      end
    end
  end
end
