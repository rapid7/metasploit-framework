require 'windows/api'

module Windows
  module Window
    module Dialog
      API.auto_namespace = 'Windows::Window::Dialog'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      MB_OK                        = 0x00000000
      MB_OKCANCEL                  = 0x00000001
      MB_ABORTRETRYIGNORE          = 0x00000002
      MB_YESNOCANCEL               = 0x00000003
      MB_YESNO                     = 0x00000004
      MB_RETRYCANCEL               = 0x00000005
      MB_CANCELTRYCONTINUE         = 0x00000006
      MB_ICONHAND                  = 0x00000010
      MB_ICONQUESTION              = 0x00000020
      MB_ICONEXCLAMATION           = 0x00000030
      MB_ICONASTERISK              = 0x00000040
      MB_USERICON                  = 0x00000080
      MB_ICONWARNING               = MB_ICONEXCLAMATION
      MB_ICONERROR                 = MB_ICONHAND
      MB_ICONINFORMATION           = MB_ICONASTERISK
      MB_ICONSTOP                  = MB_ICONHAND
      MB_DEFBUTTON1                = 0x00000000
      MB_DEFBUTTON2                = 0x00000100
      MB_DEFBUTTON3                = 0x00000200
      MB_DEFBUTTON4                = 0x00000300
      MB_APPLMODAL                 = 0x00000000
      MB_SYSTEMMODAL               = 0x00001000
      MB_TASKMODAL                 = 0x00002000
      MB_HELP                      = 0x00004000
      MB_NOFOCUS                   = 0x00008000
      MB_SETFOREGROUND             = 0x00010000
      MB_DEFAULT_DESKTOP_ONLY      = 0x00020000
      MB_TOPMOST                   = 0x00040000
      MB_RIGHT                     = 0x00080000
      MB_RTLREADING                = 0x00100000
      MB_SERVICE_NOTIFICATION      = 0x00200000 # Assume Win2k or later
      MB_SERVICE_NOTIFICATION_NT3X = 0x00040000
      MB_TYPEMASK                  = 0x0000000F
      MB_ICONMASK                  = 0x000000F0
      MB_DEFMASK                   = 0x00000F00
      MB_MODEMASK                  = 0x00003000
      MB_MISCMASK                  = 0x0000C000

      API.new('CreateDialogIndirectParam', 'LPLKL', 'L', 'user32')
      API.new('CreateDialogParam', 'LPLKL', 'L', 'user32')
      API.new('DialogBoxIndirectParam', 'LPLKL', 'P', 'user32')
      API.new('DialogBoxParam', 'LPLKL', 'P', 'user32')
      API.new('EndDialog', 'LP', 'B', 'user32')
      API.new('GetDialogBaseUnits', 'V', 'L', 'user32')
      API.new('GetDlgCtrlID', 'L', 'I', 'user32')
      API.new('GetDlgItem', 'LI', 'L', 'user32')
      API.new('GetDlgItemInt', 'LIPI', 'I', 'user32')
      API.new('GetDlgItemText', 'LIPI', 'I', 'user32')
      API.new('GetNextDlgGroupItem', 'LLI', 'L', 'user32')
      API.new('GetNextDlgTabItem', 'LLI', 'L', 'user32')
      API.new('IsDialogMessage', 'LP', 'B', 'user32')
      API.new('MapDialogRect', 'LP', 'B', 'user32')
      API.new('MessageBox', 'LPPI', 'I', 'user32')
      API.new('MessageBoxEx', 'LPPII', 'I', 'user32')
      API.new('MessageBoxIndirect', 'P', 'I', 'user32')
      API.new('SendDlgItemMessage', 'LIILL', 'L', 'user32')
      API.new('SetDlgItemInt', 'LIII', 'L', 'user32')
      API.new('SetDlgItemText', 'LIP', 'B', 'user32')

      # Macros from WinUser.h

      def CreateDialog(hInstance, lpName, hParent, lpDialogFunc)
        CreateDialogParam.call(hInstance, lpName, hParent, lpDialogFunc, 0)
      end

      def CreateDialogIndirect(hInst, lpTemp, hPar, lpDialFunc)
        CreateDialogIndirectParam.call(hInst, lpTemp, hPar, lpDialFunc, 0)
      end

      def DialogBox(hInstance, lpTemp, hParent, lpDialogFunc)
        DialogBoxParam.call(hInstance, lpTemp, hParent, lpDialogFunc, 0)
      end

      def DialogBoxIndirect(hInst, lpTemp, hParent, lpDialogFunc)
        DialogBoxParamIndirect.call(hInst, lpTemp, hParent, lpDialogFunc, 0)
      end
    end
  end
end
