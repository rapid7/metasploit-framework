require 'windows/api'

module Windows
  module GDI
    module MetaFile
      API.auto_namespace = 'Windows::GDI::MetaFile'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      API.new('CloseEnhMetaFile', 'L', 'L', 'gdi32')
      API.new('CloseMetaFile', 'L', 'L', 'gdi32')
      API.new('CopyEnhMetaFile', 'LS', 'L', 'gdi32')
      API.new('CopyMetaFile', 'LS', 'L', 'gdi32')
      API.new('CreateEnhMetaFile', 'LSPS', 'L', 'gdi32')
      API.new('CreateMetaFile', 'S', 'L', 'gdi32')
      API.new('DeleteEnhMetaFile', 'L', 'B', 'gdi32')
      API.new('DeleteMetaFile', 'L', 'B', 'gdi32')
      API.new('EnumEnhMetaFile', 'LLKKP', 'B', 'gdi32')
      API.new('EnumMetaFile', 'LLKP', 'B', 'gdi32')
      API.new('GdiComment', 'LLP', 'B', 'gdi32')
      API.new('GetEnhMetaFile', 'S', 'L', 'gdi32')
      API.new('GetEnhMetaFileBits', 'LLP', 'L', 'gdi32')
      API.new('GetEnhMetaFileDescription', 'LLP', 'L', 'gdi32')
      API.new('GetEnhMetaFileHeader', 'LLP', 'L', 'gdi32')
      API.new('GetEnhMetaFilePaletteEntries', 'LLP', 'L', 'gdi32')
      API.new('GetMetaFileBitsEx', 'LLP', 'L', 'gdi32')
      API.new('GetWinMetaFileBits', 'LLPIL', 'L', 'gdi32')
      API.new('PlayEnhMetaFile', 'LLP', 'L', 'gdi32')
      API.new('PlayEnhMetaFileRecord', 'LLPL', 'L', 'gdi32')
      API.new('PlayMetaFile', 'LL', 'B', 'gdi32')
      API.new('PlayMetaFileRecord', 'LPPL', 'B', 'gdi32')
      API.new('SetEnhMetaFileBits', 'LP', 'L', 'gdi32')
      API.new('SetMetaFileBitsEx', 'LP', 'L', 'gdi32')
      API.new('SetWinMetaFileBits', 'LPLP', 'L', 'gdi32')
    end
  end
end
