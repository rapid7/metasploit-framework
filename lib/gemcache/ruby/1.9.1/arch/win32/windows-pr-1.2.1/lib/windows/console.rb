require 'windows/api'

module Windows
   module Console
      API.auto_namespace = 'Windows::Console'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      CTRL_C_EVENT        = 0
      CTRL_BREAK_EVENT    = 1
      CTRL_CLOSE_EVENT    = 2
      CTRL_LOGOFF_EVENT   = 5
      CTRL_SHUTDOWN_EVENT = 6

      ENABLE_PROCESSED_INPUT    = 0x0001
      ENABLE_LINE_INPUT         = 0x0002
      ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
      ENABLE_ECHO_INPUT         = 0x0004
      ENABLE_WINDOW_INPUT       = 0x0008
      ENABLE_MOUSE_INPUT        = 0x0010
      ENABLE_INSERT_MODE        = 0x0020
      ENABLE_QUICK_EDIT_MODE    = 0x0040

      STD_INPUT_HANDLE  = -10
      STD_OUTPUT_HANDLE = -11
      STD_ERROR_HANDLE  = -12
      
      # Console window constants
      FOREGROUND_BLUE            = 0x0001
      FOREGROUND_GREEN           = 0x0002
      FOREGROUND_RED             = 0x0004
      FOREGROUND_INTENSITY       = 0x0008
      BACKGROUND_BLUE            = 0x0010
      BACKGROUND_GREEN           = 0x0020
      BACKGROUND_RED             = 0x0040
      BACKGROUND_INTENSITY       = 0x0080
      COMMON_LVB_LEADING_BYTE    = 0x0100
      COMMON_LVB_TRAILING_BYTE   = 0x0200
      COMMON_LVB_GRID_HORIZONTAL = 0x0400
      COMMON_LVB_GRID_LVERTICAL  = 0x0800
      COMMON_LVB_GRID_RVERTICAL  = 0x1000
      COMMON_LVB_REVERSE_VIDEO   = 0x4000
      COMMON_LVB_UNDERSCORE      = 0x8000
      COMMON_LVB_SBCSDBCS        = 0x0300

      CONSOLE_FULLSCREEN          = 1
      CONSOLE_OVERSTRIKE          = 1
      CONSOLE_FULLSCREEN_HARDWARE = 2
      
      API.new('AddConsoleAlias', 'PPP', 'B')
      API.new('AllocConsole', 'V', 'B')     
      API.new('CreateConsoleScreenBuffer', 'LLPLP', 'L')
      API.new('FillConsoleOutputAttribute', 'LILLP', 'B')
      API.new('FillConsoleOutputCharacter', 'LILLP', 'B')
      API.new('FlushConsoleInputBuffer', 'L', 'B')
      API.new('FreeConsole', 'V', 'B')
      API.new('GenerateConsoleCtrlEvent', 'LL', 'B')
      API.new('GetConsoleAlias', 'PPLP', 'L')
      API.new('GetConsoleAliases', 'PLP', 'L')
      API.new('GetConsoleAliasesLength', 'P', 'L')
      API.new('GetConsoleAliasExes', 'PL', 'L')
      API.new('GetConsoleAliasExesLength', 'V', 'L')
      API.new('GetConsoleCP', 'V', 'I')
      API.new('GetConsoleCursorInfo', 'LP', 'B')     
      API.new('GetConsoleMode', 'LP', 'B')
      API.new('GetConsoleOutputCP', 'V', 'I')    
      API.new('GetConsoleScreenBufferInfo', 'LP', 'B')     
      API.new('GetConsoleTitle', 'PL', 'L')
      API.new('GetConsoleWindow', 'V', 'L')     
      API.new('GetLargestConsoleWindowSize', 'L', 'L')
      API.new('GetNumberOfConsoleInputEvents', 'LP', 'B')
      API.new('GetNumberOfConsoleMouseButtons', 'L', 'B')
      API.new('GetStdHandle', 'L', 'L')
      API.new('PeekConsoleInput', 'LPLP', 'B')
      API.new('ReadConsole', 'LPLPP', 'B')
      API.new('ReadConsoleInput', 'LPLP', 'B')
      API.new('ReadConsoleOutput', 'LPLLP', 'B')
      API.new('ReadConsoleOutputAttribute', 'LPLLP', 'B')
      API.new('ReadConsoleOutputCharacter', 'LPLLP', 'B')
      API.new('ScrollConsoleScreenBuffer', 'LPPLP', 'B')
      API.new('SetConsoleActiveScreenBuffer', 'L', 'B')
      API.new('SetConsoleCP', 'L', 'B')
      API.new('SetConsoleCtrlHandler', 'KI', 'B')
      API.new('SetConsoleCursorInfo', 'LP', 'B')
      API.new('SetConsoleCursorPosition', 'LP', 'B')      
      API.new('SetConsoleMode', 'LL', 'B')
      API.new('SetConsoleOutputCP', 'I', 'B')
      API.new('SetConsoleScreenBufferSize', 'LL', 'B')
      API.new('SetConsoleTextAttribute', 'LL', 'B')
      API.new('SetConsoleTitle', 'P', 'B')
      API.new('SetConsoleWindowInfo', 'LIP', 'B')
      API.new('SetStdHandle', 'LL', 'B')
      API.new('WriteConsole', 'LPLPP', 'B')
      API.new('WriteConsoleInput', 'LPLP', 'B')
      API.new('WriteConsoleOutput', 'LPLLP', 'B')
      API.new('WriteConsoleOutputAttribute', 'LPLLP', 'B')
      API.new('WriteConsoleOutputCharacter', 'LPLLP', 'B')
      
      begin
         API.new('AttachConsole', 'L', 'B')
         API.new('GetConsoleDisplayMode', 'P', 'L')
         API.new('GetConsoleFontSize', 'LL', 'L')
         API.new('GetConsoleProcessList', 'PL', 'L')
         API.new('GetConsoleSelectionInfo', 'P', 'B')
         API.new('GetCurrentConsoleFont' , 'LIP', 'B')
         API.new('SetConsoleDisplayMode', 'LLP', 'B')
      rescue Win32::API::LoadLibraryError
         # Windows XP or later
      end
   end
end
