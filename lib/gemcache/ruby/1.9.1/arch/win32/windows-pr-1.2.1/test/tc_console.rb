######################################################################
# tc_console.rb
#
# Test case for the Windows::Console module.
######################################################################
require 'windows/console'
require 'test/unit'

class TC_Windows_Console < Test::Unit::TestCase
   include Windows::Console

   def setup
      @ver = `ver`.chomp
   end

   def test_numeric_constants
      assert_equal(0, CTRL_C_EVENT)
      assert_equal(1, CTRL_BREAK_EVENT)
      assert_equal(5, CTRL_LOGOFF_EVENT)
      assert_equal(6, CTRL_SHUTDOWN_EVENT)
      assert_equal(0x0001, ENABLE_PROCESSED_INPUT)
      assert_equal(0x0002, ENABLE_LINE_INPUT)
      assert_equal(0x0002, ENABLE_WRAP_AT_EOL_OUTPUT)
      assert_equal(0x0004, ENABLE_ECHO_INPUT)
      assert_equal(0x0008, ENABLE_WINDOW_INPUT)
      assert_equal(0x0010, ENABLE_MOUSE_INPUT)
      assert_equal(0x0020, ENABLE_INSERT_MODE)
      assert_equal(0x0040, ENABLE_QUICK_EDIT_MODE)
      assert_equal(-10, STD_INPUT_HANDLE)
      assert_equal(-11, STD_OUTPUT_HANDLE)
      assert_equal(-12, STD_ERROR_HANDLE)
   end

   def test_method_constants
      assert_respond_to(self, :AddConsoleAlias)
      assert_respond_to(self, :AllocConsole)
      assert_respond_to(self, :CreateConsoleScreenBuffer)
      assert_respond_to(self, :FillConsoleOutputAttribute)
      assert_respond_to(self, :FillConsoleOutputCharacter)
      assert_respond_to(self, :FlushConsoleInputBuffer)
      assert_respond_to(self, :FreeConsole)
      assert_respond_to(self, :GenerateConsoleCtrlEvent)
      assert_respond_to(self, :GetConsoleAlias)
      assert_respond_to(self, :GetConsoleAliases)
      assert_respond_to(self, :GetConsoleAliasesLength)
      assert_respond_to(self, :GetConsoleAliasExes)
      assert_respond_to(self, :GetConsoleAliasExesLength)
      assert_respond_to(self, :GetConsoleCP)
      assert_respond_to(self, :GetConsoleCursorInfo)
      assert_respond_to(self, :GetConsoleMode)
      assert_respond_to(self, :GetConsoleOutputCP)
      assert_respond_to(self, :GetConsoleScreenBufferInfo)
      assert_respond_to(self, :GetConsoleTitle)
      assert_respond_to(self, :GetConsoleWindow)
      assert_respond_to(self, :GetLargestConsoleWindowSize)
      assert_respond_to(self, :GetNumberOfConsoleInputEvents)
      assert_respond_to(self, :GetNumberOfConsoleMouseButtons)
      assert_respond_to(self, :GetStdHandle)
      assert_respond_to(self, :PeekConsoleInput)
      assert_respond_to(self, :ReadConsole)
      assert_respond_to(self, :ReadConsoleInput)
      assert_respond_to(self, :ReadConsoleOutput)
      assert_respond_to(self, :ReadConsoleOutputAttribute)
      assert_respond_to(self, :ReadConsoleOutputCharacter)
      assert_respond_to(self, :ScrollConsoleScreenBuffer)
      assert_respond_to(self, :SetConsoleActiveScreenBuffer)
      assert_respond_to(self, :SetConsoleCP)
      assert_respond_to(self, :SetConsoleCtrlHandler)
      assert_respond_to(self, :SetConsoleCursorInfo)
      assert_respond_to(self, :SetConsoleCursorPosition)
      assert_respond_to(self, :SetConsoleMode)
      assert_respond_to(self, :SetConsoleOutputCP)
      assert_respond_to(self, :SetConsoleScreenBufferSize)
      assert_respond_to(self, :SetConsoleTextAttribute)
      assert_respond_to(self, :SetConsoleTitle)
      assert_respond_to(self, :SetConsoleWindowInfo)
      assert_respond_to(self, :SetStdHandle)
      assert_respond_to(self, :WriteConsole)
      assert_respond_to(self, :WriteConsoleInput)
      assert_respond_to(self, :WriteConsoleOutput)
      assert_respond_to(self, :WriteConsoleOutputAttribute)
      assert_respond_to(self, :WriteConsoleOutputCharacter)
   end

   def test_method_constants_xp_or_later
      if @ver =~ /XP/
         assert_respond_to(self, :AttachConsole)
         assert_respond_to(self, :GetConsoleDisplayMode)
         assert_respond_to(self, :GetConsoleFontSize)
         assert_respond_to(self, :GetConsoleProcessList)
         assert_respond_to(self, :GetConsoleSelectionInfo)
         assert_respond_to(self, :GetCurrentConsoleFont)
         assert_respond_to(self, :SetConsoleDisplayMode)
      end
   end

   def test_explicit_ansi
      assert_respond_to(self, :GetConsoleAliasA)
   end

   def test_explicit_unicode
      assert_respond_to(self, :GetConsoleAliasW)
   end

   def teardown
      @ver = nil
   end
end
