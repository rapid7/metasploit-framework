############################################################################
# test_windows_api.rb
#
# Test case for the Windows::API class. You should run this as Rake task,
# i.e. 'rake test', instead of running it directly.
############################################################################
require 'windows/api'
require 'test/unit'
include Windows

module Windows
   module Test
      API.auto_namespace = 'Windows::Test'
      API.auto_unicode   = true
      API.auto_method    = true
      API.auto_constant  = true
      $test_method = API.new('GetCurrentDirectory', 'PP', 'L')
   end

   module Foo
      API.auto_namespace = 'Windows::Foo'
      API.auto_unicode  = false
      API.auto_method   = false
      API.auto_constant = false
      $foo_method = API.new('GetSystemDirectory', 'PL', 'L')
   end

   module Bar
      API.auto_namespace = 'Windows::Bar'
      API.auto_constant = true
      API.auto_method   = true
      $bar_method = API.new('GetUserName', 'PP', 'I', 'advapi32')
   end

   module Baz
      API.auto_namespace = 'Windows::Baz'
      API.auto_constant  = true
      API.auto_method    = true

      $strstr = API.new('strstr', 'PP', 'P', 'msvcrt')
      $umask  = API.new('_umask', 'I', 'I', 'msvcrt')
      $wave   = API.new('waveOutGetNumDevs', 'V', 'I', 'winmm')
      $read   = API.new('ReadDirectoryChangesW', 'LPLILPPP', 'B') # No ANSI equivalent
   end
end

class TC_Windows_API < Test::Unit::TestCase
   include Windows::Test
   include Windows::Foo
   include Windows::Bar
   include Windows::Baz

   def setup
      @buf = 0.chr * 256
      @runtimes = ['msvcrt', 'msvcr80', 'msvcr90']
   end

   def test_version
      assert_equal('0.4.1', API::VERSION)
   end

   def test_full_data_types
      assert_nothing_raised{
         API.new('GetWindowsDirectory', ['LPTSTR', 'UINT'], 'BOOL')
      }
   end

   def test_msvcrt_constant
      assert_equal(true, @runtimes.include?(Windows::MSVCRT_DLL))
   end

   # Validate that functions like 'strstr' get an uppercase constant like 'Strstr'
   def test_lower_case_to_capitalized_constant
      assert_not_nil(Windows::Baz::Strstr)
      assert_not_nil(Windows::Baz::Umask)
      assert_not_nil(Windows::Baz::WaveOutGetNumDevs)
   end

   def test_explicit_wide_function_only
      assert_not_nil(Windows::Baz::ReadDirectoryChangesW)
      assert_equal(false, Windows::Baz.constants.include?('ReadDirectoryChanges'))
      assert_equal(false, Windows::Baz.constants.include?('ReadDirectoryChangesA'))
   end

   def test_lower_case_auto_methods
      assert_respond_to(self, :strstr)
      assert_respond_to(self, :umask)
      assert_respond_to(self, :_umask)
      assert_respond_to(self, :waveOutGetNumDevs)
      assert_equal('llo', strstr('hello', 'l'))
   end

   def test_auto_unicode
      assert_not_nil(Windows::Bar::GetUserName)
      assert_equal(true, self.respond_to?(:GetUserName))
      assert_equal(false, self.respond_to?(:GetUserNameA))
      assert_equal(false, self.respond_to?(:GetUserNameW))
   end

   def test_auto_constant
      assert_not_nil(Windows::Test::GetCurrentDirectory)
      assert_not_nil(Windows::Bar::GetUserName)

      assert_kind_of(Win32::API, Windows::Test::GetCurrentDirectory)
      assert_respond_to(Windows::Test::GetCurrentDirectory, :call)
   end

   def test_auto_method
      assert_respond_to(self, :GetCurrentDirectory)
      assert_respond_to(self, :GetCurrentDirectoryA)
      assert_respond_to(self, :GetCurrentDirectoryW)

      assert_equal(false, self.respond_to?(:GetSystemDirectory))
      assert_equal(false, self.respond_to?(:GetSystemDirectoryA))
      assert_equal(false, self.respond_to?(:GetSystemDirectoryW))
   end

   def test_call
      assert_respond_to($test_method, :call)
      assert_respond_to($foo_method, :call)
      assert_nothing_raised{ $test_method.call(@buf.length, @buf) }
      assert_nothing_raised{ $foo_method.call(@buf, @buf.length) }
   end

   def test_dll_name
      assert_respond_to($test_method, :dll_name)
      assert_equal('kernel32', $test_method.dll_name)
   end

   def test_function_name
      assert_respond_to($test_method, :function_name)
      assert_equal('GetCurrentDirectory', $test_method.function_name)
   end

   def test_prototype
      assert_respond_to($test_method, :prototype)
      assert_equal(['P', 'P'], $test_method.prototype)
   end

   def test_return_type
      assert_respond_to($test_method, :return_type)
      assert_equal('L', $test_method.return_type)
   end

   def test_effective_function_name
      assert_respond_to($test_method, :effective_function_name)
      assert_equal('GetCurrentDirectoryA', $test_method.effective_function_name)
      assert_equal('strstr', $strstr.effective_function_name)
      assert_equal('waveOutGetNumDevs', $wave.effective_function_name)
      assert_equal('ReadDirectoryChangesW', $read.effective_function_name)
   end

   def test_bad_prototype_raises_error
      assert_raise(Win32::API::PrototypeError){ Windows::API.new('GetCurrentDirectory', 'XL', 'L') }
      assert_raise(Win32::API::PrototypeError){ Windows::API.new('GetCurrentDirectory', 'PL', 'X') }
   end

   def test_bad_function_raises_error
      assert_raise(Win32::API::LoadLibraryError){ Windows::API.new('GetCurrentFooBar', 'LL', 'L') }
   end

   def teardown
      @buf = nil
      @runtimes = nil
   end
end
