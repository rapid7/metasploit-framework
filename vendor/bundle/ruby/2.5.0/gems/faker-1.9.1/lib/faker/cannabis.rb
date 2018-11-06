# frozen_string_literal: true

module Faker
  class Cannabis < Base
    def self.strain
      fetch('cannabis.strains')
    end

    def self.cannabinoid_abbreviation
      fetch('cannabis.cannabinoid_abbreviations')
    end

    def self.cannabinoid
      fetch('cannabis.cannabinoids')
    end

    def self.terpene
      fetch('cannabis.terpenes')
    end

    def self.medical_use
      fetch('cannabis.medical_uses')
    end

    def self.health_benefit
      fetch('cannabis.health_benefits')
    end

    def self.category
      fetch('cannabis.categories')
    end

    def self.type
      fetch('cannabis.types')
    end

    def self.buzzword
      fetch('cannabis.buzzwords')
    end

  end
end
