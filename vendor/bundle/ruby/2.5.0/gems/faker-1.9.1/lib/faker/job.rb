module Faker
  class Job < Base
    flexible :job

    class << self
      def title
        parse('job.title')
      end

      def position
        fetch('job.position')
      end

      def field
        fetch('job.field')
      end

      def key_skill
        fetch('job.key_skills')
      end
    end
  end
end
