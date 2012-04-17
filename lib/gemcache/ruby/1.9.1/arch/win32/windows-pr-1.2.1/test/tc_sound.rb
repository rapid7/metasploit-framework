#####################################################################
# tc_sound.rb
#
# Test case for the Windows::Sound module.
#####################################################################
require 'windows/sound'
require 'test/unit'

class SoundFoo
   include Windows::Sound
end

class TC_Windows_Sound < Test::Unit::TestCase
   def setup
      @foo = SoundFoo.new
   end

   def test_numeric_constants
      assert_equal(0, SoundFoo::SND_SYNC)
      assert_equal(1, SoundFoo::SND_ASYNC)
      assert_equal(2, SoundFoo::SND_NODEFAULT)
      assert_equal(4, SoundFoo::SND_MEMORY)
      assert_equal(8, SoundFoo::SND_LOOP)
      assert_equal(16, SoundFoo::SND_NOSTOP)
   end
   
   def test_method_constants
      assert_not_nil(SoundFoo::Beep)
      assert_not_nil(SoundFoo::PlaySound)
      assert_not_nil(SoundFoo::WaveOutSetVolume)
      assert_not_nil(SoundFoo::WaveOutGetVolume)
   end
   
   def teardown
      @foo = nil
   end
end
