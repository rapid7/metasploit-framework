require 'windows/api'

module Windows
  module GDI
    module PaintingDrawing
      API.auto_namespace = 'Windows::GDI::PaintingDrawing'
      API.auto_constant = true
      API.auto_method   = true
      API.auto_unicode  = false

      private

      # Flags for DrawCaption
      DC_ACTIVE   = 0x0001
      DC_SMALLCAP = 0x0002
      DC_ICON     = 0x0004
      DC_TEXT     = 0x0008
      DC_INBUTTON = 0x0010
      DC_GRADIENT = 0x0020
      DC_BUTTONS  = 0x1000

      # 3D border styles
      BDR_RAISEDOUTER = 0x0001
      BDR_SUNKENOUTER = 0x0002
      BDR_RAISEDINNER = 0x0004
      BDR_SUNKENINNER = 0x0008

      BDR_OUTER  = (BDR_RAISEDOUTER | BDR_SUNKENOUTER)
      BDR_INNER  = (BDR_RAISEDINNER | BDR_SUNKENINNER)
      BDR_RAISED = (BDR_RAISEDOUTER | BDR_RAISEDINNER)
      BDR_SUNKEN = (BDR_SUNKENOUTER | BDR_SUNKENINNER)

      EDGE_RAISED = (BDR_RAISEDOUTER | BDR_RAISEDINNER)
      EDGE_SUNKEN = (BDR_SUNKENOUTER | BDR_SUNKENINNER)
      EDGE_ETCHED = (BDR_SUNKENOUTER | BDR_RAISEDINNER)
      EDGE_BUMP   = (BDR_RAISEDOUTER | BDR_SUNKENINNER)

      # Border flags
      BF_LEFT   = 0x0001
      BF_TOP    = 0x0002
      BF_RIGHT  = 0x0004
      BF_BOTTOM = 0x0008

      BF_TOPLEFT     = (BF_TOP | BF_LEFT)
      BF_TOPRIGHT    = (BF_TOP | BF_RIGHT)
      BF_BOTTOMLEFT  = (BF_BOTTOM | BF_LEFT)
      BF_BOTTOMRIGHT = (BF_BOTTOM | BF_RIGHT)
      BF_RECT        = (BF_LEFT | BF_TOP | BF_RIGHT | BF_BOTTOM)

      BF_DIAGONAL = 0x0010

      BF_DIAGONAL_ENDTOPRIGHT    = (BF_DIAGONAL | BF_TOP | BF_RIGHT)
      BF_DIAGONAL_ENDTOPLEFT     = (BF_DIAGONAL | BF_TOP | BF_LEFT)
      BF_DIAGONAL_ENDBOTTOMLEFT  = (BF_DIAGONAL | BF_BOTTOM | BF_LEFT)
      BF_DIAGONAL_ENDBOTTOMRIGHT = (BF_DIAGONAL | BF_BOTTOM | BF_RIGHT)

      BF_MIDDLE = 0x0800 # Fill in the middle
      BF_SOFT   = 0x1000 # For softer buttons
      BF_ADJUST = 0x2000 # Calculate the space left over
      BF_FLAT   = 0x4000 # For flat rather than 3D borders
      BF_MONO   = 0x8000 # For monochrome borders

      # Flags for DrawFrameControl
      DFC_CAPTION   = 1
      DFC_MENU      = 2
      DFC_SCROLL    = 3
      DFC_BUTTON    = 4
      DFC_POPUPMENU = 5

      DFCS_CAPTIONCLOSE   = 0x0000
      DFCS_CAPTIONMIN     = 0x0001
      DFCS_CAPTIONMAX     = 0x0002
      DFCS_CAPTIONRESTORE = 0x0003
      DFCS_CAPTIONHELP    = 0x0004

      DFCS_MENUARROW           = 0x0000
      DFCS_MENUCHECK           = 0x0001
      DFCS_MENUBULLET          = 0x0002
      DFCS_MENUARROWRIGHT      = 0x0004
      DFCS_SCROLLUP            = 0x0000
      DFCS_SCROLLDOWN          = 0x0001
      DFCS_SCROLLLEFT          = 0x0002
      DFCS_SCROLLRIGHT         = 0x0003
      DFCS_SCROLLCOMBOBOX      = 0x0005
      DFCS_SCROLLSIZEGRIP      = 0x0008
      DFCS_SCROLLSIZEGRIPRIGHT = 0x0010

      DFCS_BUTTONCHECK      = 0x0000
      DFCS_BUTTONRADIOIMAGE = 0x0001
      DFCS_BUTTONRADIOMASK  = 0x0002
      DFCS_BUTTONRADIO      = 0x0004
      DFCS_BUTTON3STATE     = 0x0008
      DFCS_BUTTONPUSH       = 0x0010

      DFCS_INACTIVE = 0x0100
      DFCS_PUSHED   = 0x0200
      DFCS_CHECKED  = 0x0400

      DFCS_TRANSPARENT = 0x0800
      DFCS_HOT         = 0x1000

      DFCS_ADJUSTRECT = 0x2000
      DFCS_FLAT       = 0x4000
      DFCS_MONO       = 0x8000

      API.new('BeginPaint', 'LP', 'L', 'user32')
      API.new('GetWindowDC', 'L', 'L', 'user32')
      API.new('DrawAnimatedRects', 'LIPP', 'B', 'user32')
      API.new('DrawCaption', 'LLPL', 'B', 'user32')
      API.new('DrawEdge', 'LPII', 'B', 'user32')
      API.new('DrawFocusRect', 'LP', 'B', 'user32')
      API.new('DrawFrameControl', 'LPLL', 'B', 'user32')
    end
  end
end
