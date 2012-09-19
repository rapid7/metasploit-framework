require 'windows/api'

module Windows
  module Clipboard
    API.auto_namespace = 'Windows::Clipboard'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    CF_TEXT            = 1
    CF_BITMAP          = 2
    CF_METAFILEPICT    = 3
    CF_SYLK            = 4
    CF_DIF             = 5
    CF_TIFF            = 6
    CF_OEMTEXT         = 7
    CF_DIB             = 8
    CF_PALETTE         = 9
    CF_PENDATA         = 10
    CF_RIFF            = 11
    CF_WAVE            = 12
    CF_UNICODETEXT     = 13
    CF_ENHMETAFILE     = 14
    CF_HDROP           = 15
    CF_LOCALE          = 16
    CF_MAX             = 18 # Assume Windows 2000 or later
    CF_OWNERDISPLAY    = 0x0080
    CF_DSPTEXT         = 0x0081
    CF_DSPBITMAP       = 0x0082
    CF_DSPMETAFILEPICT = 0x0083
    CF_DSPENHMETAFILE  = 0x008E

    API.new('ChangeClipboardChain', 'LL', 'B', 'user32')
    API.new('CloseClipboard', 'V', 'B', 'user32')
    API.new('CountClipboardFormats', 'V', 'I', 'user32')
    API.new('EmptyClipboard', 'V', 'B', 'user32')
    API.new('EnumClipboardFormats', 'I', 'I', 'user32')
    API.new('GetClipboardData', 'I', 'L', 'user32')
    API.new('GetClipboardFormatName', 'IPI', 'I', 'user32')
    API.new('GetClipboardOwner', 'V', 'L', 'user32')
    API.new('GetClipboardSequenceNumber', 'V', 'L', 'user32')
    API.new('GetClipboardViewer', 'V', 'L', 'user32')
    API.new('GetOpenClipboardWindow', 'V', 'L', 'user32')
    API.new('GetPriorityClipboardFormat', 'PI', 'I', 'user32')
    API.new('IsClipboardFormatAvailable', 'I', 'B', 'user32')
    API.new('OpenClipboard', 'L', 'B', 'user32')
    API.new('RegisterClipboardFormat', 'S', 'I', 'user32')
    API.new('SetClipboardData', 'IL', 'L', 'user32')
    API.new('SetClipboardViewer', 'L', 'L', 'user32')

    begin
      API.new('AddClipboardFormatListener', 'L', 'B', 'user32')
      API.new('GetUpdatedClipboardFormats', 'PIP', 'I', 'user32')
      API.new('RemoveClipboardFormatListener', 'L', 'B', 'user32')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
  end
end
