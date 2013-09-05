# Windows console color support
# Copyright 2011 Michael 'mihi' Schierl
# Licensed under MSF license

class WindowsConsoleColorSupport

  STD_OUTPUT_HANDLE = -11
  COLORS = [0, 4, 2, 6, 1, 5, 3, 7]
  
  def initialize(origstream)
    @origstream = origstream
    
    # initialize API
    @GetStdHandle = Win32API.new("kernel32","GetStdHandle",['L'],'L')
    @GetConsoleScreenBufferInfo = Win32API.new("kernel32","GetConsoleScreenBufferInfo",['L','P'],'L')
    @SetConsoleTextAttribute = Win32API.new("kernel32","SetConsoleTextAttribute",['L','l'],'L')
    @hConsoleHandle = @GetStdHandle.Call(STD_OUTPUT_HANDLE)
  end
  
  def write(msg)
    rest = msg
    while (rest =~ Regexp.new("([^\e]*)\e\\[([0-9;]+)m"))
      @origstream.write($1)
      rest = $' # save it now since setcolor may clobber it
      $2.split(";").each do |color|
        setcolor(color.to_i)
      end
    end
    @origstream.write(rest)
  end
  
  def flush
    @origstream.flush
  end

  def setcolor(color)
    csbi = 0.chr * 24
    @GetConsoleScreenBufferInfo.Call(@hConsoleHandle,csbi)
    wAttr = csbi[8,2].unpack('S').first
    
    case color
      when 0 # reset
        wAttr = 0x07
      when 1 # bold
        wAttr |= 0x08
      when 2 # unbold
        wAttr &= ~0x08
      when 7 # reverse
        wAttr = ((wAttr & 0x0f) << 4) | ((wAttr & 0xf0) >> 4)
      when 8 # conceal
        wAttr &= ~0x0f
      when 30 .. 37 # foreground colors
        wAttr = (wAttr & ~0x07) | COLORS[color - 30]
      when 40 .. 47 # background colors
        wAttr = (wAttr & ~0x70) | (COLORS[color - 40] << 4)
    end
    
    @SetConsoleTextAttribute.Call(@hConsoleHandle, wAttr)
  end		
end
