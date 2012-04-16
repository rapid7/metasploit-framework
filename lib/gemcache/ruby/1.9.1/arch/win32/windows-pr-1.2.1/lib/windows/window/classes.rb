require 'windows/api'

module Windows
  module Window
    module Classes
      API.auto_namespace = 'Windows::Window::Classes'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      # Class Field Offsets

      GCL_MENUNAME      = -8
      GCL_HBRBACKGROUND = -10
      GCL_HCURSOR       = -12
      GCL_HICON         = -14
      GCL_HMODULE       = -16
      GCL_CBWNDEXTRA    = -18
      GCL_CBCLSEXTRA    = -20
      GCL_WNDPROC       = -24
      GCL_STYLE         = -26
      GCW_ATOM          = -32

      # Window Field Offsets

      GWL_WNDPROC    = -4
      GWL_HINSTANCE  = -6
      GWL_HWNDPARENT = -8
      GWL_STYLE      = -16
      GWL_EXSTYLE    = -20
      GWL_USERDATA   = -21
      GWL_ID         = -12

      API.new('GetClassInfo', 'LPP', 'B', 'user32')
      API.new('GetClassInfoEx', 'LPP', 'B', 'user32')
      API.new('GetClassLong', 'LI', 'L', 'user32')
      API.new('GetClassName', 'LPI', 'I', 'user32')
      API.new('GetClassWord', 'LI', 'L', 'user32')
      API.new('GetWindowLong', 'LI', 'L', 'user32')
      API.new('RegisterClass', 'P', 'L', 'user32')
      API.new('RegisterClassEx', 'P', 'L', 'user32')
      API.new('SetClassLong', 'LIL', 'L', 'user32')
      API.new('SetClassWord', 'LIL', 'L', 'user32')
      API.new('SetWindowLong', 'LIL', 'L', 'user32')        
      API.new('UnregisterClass', 'PL', 'B', 'user32')
       
      # In 32-bit Windows, these methods are aliases
      begin
        API.new('GetWindowLongPtr', 'LI', 'L', 'user32')
        API.new('SetWindowLongPtr', 'LIP', 'L', 'user32')
      rescue Win32::API::LoadLibraryError
        alias :GetWindowLongPtr :GetWindowLong
        alias :SetWindowLongPtr :SetWindowLong
      end
   end
  end
end
