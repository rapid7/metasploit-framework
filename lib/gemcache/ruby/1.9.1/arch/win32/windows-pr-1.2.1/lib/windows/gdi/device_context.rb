require 'windows/api'

module Windows
  module GDI
    module DeviceContext
      API.auto_namespace = 'Windows::GDI::DeviceContext'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      DRIVERVERSION = 0
      TECHNOLOGY    = 2
      HORZSIZE      = 4
      VERTSIZE      = 6
      HORZRES       = 8
      VERTRES       = 10
      BITSPIXEL     = 12
      PLANES        = 14
      NUMBRUSHES    = 16
      NUMPENS       = 18
      NUMMARKERS    = 20
      NUMFONTS      = 22
      NUMCOLORS     = 24
      PDEVICESIZE   = 26
      CURVECAPS     = 28
      LINECAPS      = 30
      POLYGONALCAPS = 32
      TEXTCAPS      = 34
      CLIPCAPS      = 36
      RASTERCAPS    = 38
      ASPECTX       = 40
      ASPECTY       = 42
      ASPECTXY      = 44
    
      API.new('CreateCompatibleDC', 'L', 'L', 'gdi32')
      API.new('DeleteDC', 'L', 'B', 'gdi32')
      API.new('DeleteObject', 'L', 'B', 'gdi32')
      API.new('GetDC', 'L', 'L', 'user32')
      API.new('GetDeviceCaps', 'LI', 'I', 'gdi32')
      API.new('ReleaseDC', 'LL', 'I', 'user32')
      API.new('SelectObject', 'LL', 'L', 'gdi32')
    end
  end
end
