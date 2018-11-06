# frozen_string_literal: true

module Faker
  class DrWho < Base
    def self.character
      fetch('dr_who.character')
    end

    def self.the_doctor
      fetch('dr_who.the_doctors')
    end

    def self.actor
      fetch('dr_who.actors')
    end

    def self.catch_phrase
      fetch('dr_who.catch_phrases')
    end

    def self.quote
      fetch('dr_who.quotes')
    end

    def self.villian
      fetch('dr_who.villians')
    end

    def self.specie
      fetch('dr_who.species')
    end
  end
end
