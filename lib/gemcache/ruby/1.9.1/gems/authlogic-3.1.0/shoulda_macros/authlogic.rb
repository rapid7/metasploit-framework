# Test::Unit
# Place this file into your test/shoulda_macros directory
#
# Example:
# 
# class UserTest
#   should_have_authlogic
# end
#
# Rspec
# Place this file into your spec/support/shoulda directory
#
# Example:
#
# describe User do
#   it { should have_authlogic }
# end

module Authlogic
  module Shoulda

    module Matchers
      def have_authlogic
        HaveAuthlogic.new
      end
      alias_method :be_authentic, :have_authlogic

      class HaveAuthlogic

        def matches?(subject)
          subject.respond_to?(:password=) && subject.respond_to?(:valid_password?)
        end

        def failure_message
          "Add the line 'acts_as_authentic' to your model"
        end

        def description
          "have Authlogic"
        end
      end
      
    end
    
    module Macros
      include Matchers
      
      def should_have_authlogic
        klass = described_type rescue model_class
        matcher = HaveAuthlogic.new
        
        should matcher.description do
          assert matcher.matches?(klass.new), matcher.failure_message
        end
      end
      alias_method :should_be_authentic, :should_have_authlogic
      
    end
    
  end
end

if defined? Spec
  Spec::Runner.configure do |config|
    config.include(Authlogic::Shoulda::Matchers)
  end
else
  Test::Unit::TestCase.class_eval { extend Authlogic::Shoulda::Macros }
end
