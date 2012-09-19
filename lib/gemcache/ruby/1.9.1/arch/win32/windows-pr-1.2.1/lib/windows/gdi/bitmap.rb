require 'windows/api'

module Windows
  module GDI
    module Bitmap
      API.auto_namespace = 'Windows::GDI::Bitmap'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      DIB_RGB_COLORS = 0
      DIB_PAL_COLORS = 1

      # Raster operations
      SRCCOPY      = 0x00CC0020
      SRCPAINT     = 0x00EE0086
      SRCAND       = 0x008800C6
      SRCINVERT    = 0x00660046
      SRCERASE     = 0x00440328
      NOTSRCCOPY   = 0x00330008
      NOTSRCERASE  = 0x001100A6
      MERGECOPY    = 0x00C000CA
      MERGEPAINT   = 0x00BB0226
      PATCOPY      = 0x00F00021
      PATPAINT     = 0x00FB0A09
      PATINVERT    = 0x005A0049
      STINVERT    = 0x00550009
      BLACKNESS    = 0x00000042
      WHITENESS    = 0x00FF0062
       
      API.new('AlphaBlend', 'LIIIILIIIIL', 'B', 'msimg32')
      API.new('BitBlt', 'LIIIILIIL', 'B', 'gdi32')
      API.new('CreateBitmap', 'IILLP', 'L', 'gdi32')
      API.new('CreateBitmapIndirect', 'P', 'L', 'gdi32')
      API.new('CreateCompatibleBitmap', 'LII', 'L', 'gdi32')
      API.new('CreateDIBitmap', 'LLLPPL', 'L', 'gdi32')
      API.new('CreateDIBSection', 'LPLPLL', 'L', 'gdi32')
      API.new('CreateDiscardableBitmap', 'LII', 'L', 'gdi32')
      API.new('ExtFloodFill', 'LIILL', 'B', 'gdi32')
      API.new('FloodFill', 'LIIL', 'B', 'gdi32')
      API.new('GetBitmapDimensionEx', 'LP', 'B', 'gdi32')
      API.new('GetDIBColorTable', 'LLLP', 'L', 'gdi32')
      API.new('GetDIBits', 'LLIIPPI', 'I', 'gdi32')
      API.new('GetPixel', 'LII', 'L', 'gdi32')
      API.new('GetStretchBltMode', 'L', 'I', 'gdi32')
      API.new('GradientFill', 'LLLLLL', 'B', 'msimg32')
      API.new('LoadBitmap', 'LP', 'L', 'user32')
      API.new('MaskBlt', 'LIIIILIILIIL', 'B', 'gdi32')
      API.new('PlgBlt', 'LPLIIIILII', 'B', 'gdi32')
      API.new('SetBitmapBits', 'LLP', 'L', 'gdi32')
      API.new('SetBitmapDimensionEx', 'LIIP', 'L', 'gdi32')
      API.new('SetDIBColorTable', 'LLLP', 'L', 'gdi32')
      API.new('SetDIBits', 'LLLLPPL', 'I', 'gdi32')
      API.new('SetDIBitsToDevice', 'LIILLIILLPPL', 'I', 'gdi32')
      API.new('SetPixel', 'LIIL', 'L', 'gdi32')
      API.new('SetPixelV', 'LIIL', 'B', 'gdi32')
      API.new('SetStretchBltMode', 'LI', 'I', 'gdi32')
      API.new('StretchBlt', 'LIIIILIIIIL', 'B', 'gdi32')
      API.new('StretchDIBits', 'LIIIIIIIIPPLL', 'I', 'gdi32')
      API.new('TransparentBlt', 'LIIIILIIIIL', 'B', 'msimg32')
    end
  end
end
