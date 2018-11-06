module Faker
  class ChuckNorris < Base
    flexible :name

    class << self
      # from: https://github.com/jenkinsci/chucknorris-plugin/blob/master/src/main/java/hudson/plugins/chucknorris/FactGenerator.java
      def fact
        fetch('chuck_norris.fact')
      end
    end
  end
end
