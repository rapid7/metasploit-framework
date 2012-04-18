############################################################################
# test_win32_api.rb
# 
# Test case for the Win32::API class. You should run this as Rake task,
# i.e. 'rake test', instead of running it directly.
############################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/api'
require 'test/unit'
include Win32

class TC_Win32_API < Test::Unit::TestCase
   def setup
      @buf = 0.chr * 260
      @gfa = API.new('GetFileAttributes', 'S', 'L')
      @gcd = API.new('GetCurrentDirectory', 'LP')
      @gle = API.new('GetLastError', 'V', 'L')
      @str = API.new('strstr', 'PP', 'P', 'msvcrt')
   end

   def test_version
      assert_equal('1.4.8', API::VERSION)
   end

   def test_constructor_basic
      assert_nothing_raised{ API.new('GetCurrentDirectory') }
      assert_nothing_raised{ API.new('GetCurrentDirectory', 'LP') }
      assert_nothing_raised{ API.new('GetCurrentDirectory', 'LP', 'L') }
      assert_nothing_raised{ API.new('GetCurrentDirectory', 'LP', 'L', 'kernel32') }
   end
 
   def test_call
      assert_respond_to(@gcd, :call)
      assert_nothing_raised{ @gcd.call(@buf.length, @buf) }
      assert_equal(Dir.pwd.tr('/', "\\"), @buf.strip)
   end
   
   def test_call_with_void
      assert_nothing_raised{ @gle.call }
      assert_nothing_raised{ @gle.call(nil) }
   end

   def test_call_return_value_on_failure
      assert_equal(0xFFFFFFFF, @gfa.call('C:/foobarbazblah'))
   end
   
   def test_dll_name
      assert_respond_to(@gcd, :dll_name)
      assert_equal('kernel32', @gcd.dll_name)
   end
   
   def test_function_name
      assert_respond_to(@gcd, :function_name)
      assert_equal('GetCurrentDirectory', @gcd.function_name)
      assert_equal('strstr', @str.function_name)
   end
   
   def test_effective_function_name_default
      assert_respond_to(@gcd, :effective_function_name)
      assert_equal('GetCurrentDirectoryA', @gcd.effective_function_name)
      assert_equal('strstr', @str.effective_function_name)
   end

   def test_effective_function_name_default_explicit_ansi
      @gcd = API.new('GetCurrentDirectoryA', 'LP')
      assert_equal('GetCurrentDirectoryA', @gcd.effective_function_name)
   end

   def test_effective_function_name_default_explicit_wide
      @gcd = API.new('GetCurrentDirectoryW', 'LP')
      assert_equal('GetCurrentDirectoryW', @gcd.effective_function_name)
   end
   
   def test_prototype
      assert_respond_to(@gcd, :prototype)
      assert_equal(['L', 'P'], @gcd.prototype)
   end
   
   def test_return_type
      assert_respond_to(@gcd, :return_type)
      assert_equal('L', @gcd.return_type)
   end
   
   def test_constructor_high_iteration
      assert_nothing_raised{
         1000.times{ API.new('GetUserName', 'P', 'P', 'advapi32') }
      }
   end
   
   def test_constructor_expected_failures
      assert_raise(ArgumentError){ API.new }
      assert_raise(ArgumentError){ API.new('GetUserName', ('L' * 21), 'X') }
      assert_raise(API::LoadLibraryError){ API.new('GetUserName', 'PL', 'I', 'foo') }
      assert_raise(API::PrototypeError){ API.new('GetUserName', 'X', 'I', 'advapi32') }
      assert_raise(API::PrototypeError){ API.new('GetUserName', 'PL', 'X', 'advapi32') }
   end

   test "constructor returns expected error message if function not found" do
     msg = "Unable to load function "
     assert_raise_message(msg + "'Zap', 'ZapA', or 'ZapW'"){ API.new('Zap') }
     assert_raise_message(msg + "'strxxx'"){ API.new('strxxx', 'P', 'L', 'msvcrt') }
   end

   test "constructor returns expected error message if prototype is invalid" do
     msg = "Illegal prototype 'X'"
     assert_raise_message(msg){ API.new('GetUserName', 'X', 'I', 'advapi32') }
   end

   test "constructor returns expected error message if return type is invalid" do
     msg = "Illegal return type 'Y'"
     assert_raise_message(msg){ API.new('GetUserName', 'PL', 'Y', 'advapi32') }
   end

   test "constructor returns expected error message if too many parameters" do
     msg = "too many parameters: 25"
     assert_raise_message(msg){ API.new('GetFileAttributes', 'S' * 25, 'L') }
   end

   test "call method returns expected error message if too many parameters" do
     msg = "wrong number of parameters: expected 2, got 3"
     assert_raise_message(msg){ @str.call('test', 'test', 'test') }
   end

   def test_call_expected_failures
      assert_raise(TypeError){ @gcd.call('test', @buf) }
   end

   def test_error_classes
      assert_not_nil(Win32::API::Error)
      assert_not_nil(Win32::API::LoadLibraryError)
      assert_not_nil(Win32::API::PrototypeError)
   end

   def test_error_class_relationships
      assert_kind_of(RuntimeError, Win32::API::Error.new)
      assert_kind_of(Win32::API::Error, Win32::API::LoadLibraryError.new)
      assert_kind_of(Win32::API::Error, Win32::API::PrototypeError.new)
   end

   def teardown
      @buf = nil
      @gcd = nil
      @gle = nil
      @str = nil
   end
end
