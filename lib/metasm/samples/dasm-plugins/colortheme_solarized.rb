#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm gui plugin: change the colortheme used in the GUI
# based on solarized: http://ethanschoonover.com/solarized/

if gui
  solarized = {
    # name => hex RRGGBB
    :base03  => '002b36',
    :base02  => '073642',
    :base01  => '586e75',
    :base00  => '657b83',
    :base0   => '839496',
    :base1   => '93a1a1',
    :base2   => 'eee8d5',
    :base3   => 'fdf6e3',
    :yellow  => 'b58900',
    :orange  => 'cb4b16',
    :red     => 'dc322f',
    :magenta => 'd33682',
    :violet  => '6c71c4',
    :blue    => '268bd2',
    :cyan    => '2aa198',
    :green   => '859900',

    # personnal additions for more contrast
    :base0C  => '094048',
    :base0D  => '00151b',

    :black   => '002b36',	# base03
    :white   => '93a1a1',	# base1

    :yellow_bg  => '5a591b',# approx mean with black + manual tweak
    :orange_bg  => '553a16',
    :red_bg     => '461b1d',
    :magenta_bg => '69305c',
    :violet_bg  => '364d7d',
    :blue_bg    => '135a84',
    :cyan_bg    => '156567',
    :green_bg   => '16510b',
  }

  # all widget's colorscheme inherits from this one
  # this is the dark background theme. For light background, change
  #  all 'baseX' into 'base0X' and 'base0X' into 'baseX'.
  default = {
    :background    => :black,
    :text          => :white,
    :instruction   => :white,
    :cursorline_bg => :base02,
    :comment       => :base01,
    :caret         => :base0,
    :label         => :violet,
    :address       => :blue,
    :hl_word_bg    => :white,
    :hl_word       => :black,
  }

  specific = {
    # widget name => colortheme
    # unspecified colors are taken from 'default'
    # still unspecified colors are left unchanged
    :listing => {
      :raw_data  => :white,
      :arrows_bg => :base02,
      :arrow_up  => :cyan,
      :arrow_dn  => :blue,
      :arrow_hl  => :orange,
    },

    :opcodes => {
      :raw_data  => :white,
    },

    :decompile => {
      :keyword   => :blue,
      :localvar  => :red,
      :globalvar => :green,
      :intrinsic => :yellow,
    },

    :coverage => {
      :code      => :red,
      :data      => :blue,
      :caret     => :yellow,
      :caret_col => :green,
    },

    :graph => {
      :background    => :base0D,
      :hlbox_bg      => :base02,
      :box_bg        => :base03,
      :cursorline_bg => :base03,
      :arrow_cond    => :green,
      :arrow_uncond  => :cyan,
      :arrow_direct  => :blue,
      :arrow_hl      => :orange,
      :box_bg_shadow => '000000',
    },

    :hex => {
      :ascii         => :white,
      :data          => :base1,
      :write_pending => :red,
      :caret_mirror  => :base0C,
    },
  }

  gui.view_indexes.each { |v|
    cs = specific[v] || {}
    view = gui.view(v)
    # keep original view ':foo => :text' colors
    legacy = view.default_color_association.dup
    # but discard actual color defs (still present as fallback anyway)
    legacy.delete_if { |k, c| c.kind_of?(::String) }
    nca = solarized.merge(legacy).merge(default).merge(cs)
    view.set_color_association(nca)
  }

  true
end
