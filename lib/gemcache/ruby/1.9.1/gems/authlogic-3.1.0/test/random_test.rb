require 'test_helper'

class RandomTest < ActiveSupport::TestCase
  def test_random_tokens_are_indeed_random
    # this might fail if you are *really* unlucky :)
    with_any_random do
      assert_not_equal Authlogic::Random.hex_token,       Authlogic::Random.hex_token
      assert_not_equal Authlogic::Random.friendly_token,  Authlogic::Random.friendly_token
    end
  end

  private
    def with_any_random(&block)
      [true, false].each {|val| with_secure_random_enabled(val, &block)}
    end

    def with_secure_random_enabled(enabled = true)
      # can't really test SecureRandom if we don't have an implementation
      return if enabled && !Authlogic::Random::SecureRandom
    
      current_sec_rand = Authlogic::Random::SecureRandom
      reload_authlogic_with_sec_random!(current_sec_rand, enabled)
  
      yield
    ensure
      reload_authlogic_with_sec_random!(current_sec_rand)
    end

    def reload_authlogic_with_sec_random!(secure_random, enabled = true)
      silence_warnings do
        secure_random.parent.const_set(secure_random.name.sub("#{secure_random.parent}::", ''), enabled ? secure_random : nil)
        load(File.dirname(__FILE__) + '/../lib/authlogic/random.rb')
      end
    end

    def silence_warnings
      old_verbose, $VERBOSE = $VERBOSE, nil
      yield
    ensure
      $VERBOSE = old_verbose
    end
end