#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm
class ARC < CPU
  def initialize(e = :little)
    super()
    @endianness = e
    @size = 32
  end

  class Reg
    include Renderable

    attr_accessor :i

    def initialize(i); @i = i end

    def ==(o)
      o.class == self.class and o.i == i
    end
  end

  # general purpose reg
  # Result R0-R1
  # Arguments R0-R7
  # Caller Saved Registers R0-R12
  # Callee Saved Registers R13-R25
  # Static chain pointer (if required) R11
  # Register for temp calculation R12
  # Global Pointer R26 (GP)
  # Frame Pointer R27 (FP)
  # Stack Pointer R28 (SP)
  # Interrupt Link Register 1 R29 (ILINK1)
  # Interrupt Link Register 2 R30 (ILINK2)
  # Branch Link Register R31 (BLINK)
  class GPR < Reg
    Sym = (0..64).map { |i| "r#{i}".to_sym }
    def symbolic; Sym[@i] end

    Render = {
      26 => 'gp', # global pointer, used to point to small sets of shared data throughout execution of a program
      27 => 'fp', # frame pointer
      28 => 'sp', # stak pointer
      29 => 'ilink1', # maskable interrupt link register
      30 => 'ilink2', # maskable interrupt link register 2
      31 => 'blink', # branch link register
      60 => 'lp_count', # loop count register (24 bits)
         # "When a destination register is set to r62 there is no destination for the result of the instruction so the
         # result is discarded. Any flag updates will still occur according to the set flags directive (.F or implicit
         #  in the instruction)."
      62 => 'zero'
    }

    def render
      if s = Render[i]
        [s]
      else
        # r0-r28 general purpose registers
        # r32-r59 reserved for extentions
        ["r#@i"]
      end
    end

  end

  class AUX < Reg
    def symbolic; "aux#{i}".to_sym end

    Render = {
      0x00  => 'status',                # Status register (Original ARCtangent-A4 processor format)
      0x01  => 'semaphore',             # Inter-process/Host semaphore register
      0x02  => 'lp_start',              # Loop start address (32-bit)
      0x03  => 'lp_end',                # Loop end address (32-bit)
      0x04  => 'identity',              # Processor Identification register
      0x05  => 'debug',                 # Debug register
      0x06  => 'pc',                    # PC register (32-bit)
      0x0A  => 'status32',              # Status register (32-bit)
      0x0B  => 'status32_l1',           # Status register save for level 1 interrupts
      0x0C  => 'status32_l2',           # Status register save for level 2 interrupts
      0x10  => 'ic_ivic',               # Cache invalidate
      0x11  => 'ic_ctrl',               # Mode bits for cache controller
      0x12  => 'mulhi',                 # High part of Multiply
      0x19  => 'ic_ivil',
      0x21  => 'timer0_cnt',            # Processor Timer 0 Count value
      0x22  => 'timer0_ctrl',           # Processor Timer 0 Control value
      0x23  => 'timer0_limit',          # Processor Timer 0 Limit value
      0x25  => 'int_vector_base',       # Interrupt Vector Base address
      0x40  => 'im_set_dc_ctrl',
      0x41  => 'aux_macmode',           # Extended Arithmetic Status and Mode
      0x43  => 'aux_irq_lv12',          # Interrupt Level Status
      0x47  => 'dc_ivdc',               # Invalidate cache
      0x48  => 'dc_ctrl',               # Cache control register
      0x49  => 'dc_ldl',                # Lock data line
      0x4A  => 'dc_ivdl',               # Invalidate data line
      0x4B  => 'dc_flsh',               # Flush data cache
      0x4C  => 'dc_fldl',               # Flush data line
      0x58  => 'dc_ram_addr',           # Access RAM address
      0x59  => 'dc_tag',                # Tag Access
      0x5A  => 'dc_wp',                 # Way Pointer Access
      0x5B  => 'dc_data',               # Data Access
      0x62  => 'crc_bcr',
      0x64  => 'dvfb_bcr',
      0x65  => 'extarith_bcr',
      0x68  => 'vecbase_bcr',
      0x69  => 'perbase_bcr',
      0x6f  => 'mmu_bcr',
      0x72  => 'd_cache_build',         # Build: Data Cache
      0x73  => 'madi_build',            # Build: Multiple ARC Debug I/F
      0x74  => 'ldstram_build',         # Build: LD/ST RAM
      0x75  => 'timer_build',           # Build: Timer
      0x76  => 'ap_build',              # Build: Actionpoints
      0x77  => 'i_cache_build',         # Build: I-Cache
      0x78  => 'addsub_build',          # Build: Saturated Add/Sub
      0x79  => 'dspram_build',          # Build: Scratch RAM & XY Memory
      0x7B  => 'multiply_build',        # Build: Multiply
      0x7C  => 'swap_build',            # Build: Swap
      0x7D  => 'norm_build',            # Build: Normalise
      0x7E  => 'minmax_build',          # Build: Min/Max
      0x7F  => 'barrel_build',          # Build: Barrel Shift
      0x100 => 'timer1_cnt',            # Processor Timer 1 Count value
      0x101 => 'timer1_ctrl',           # Processor Timer 1 Control value
      0x102 => 'timer1_limit',          # Processor Timer 1 Limit value
      0x200 => 'aux_irq_lev',           # Interrupt Level Programming
      0x201 => 'aux_irq_hint',          # Software Triggered Interrupt
      0x202 => 'aux_irq_mask',          # Masked bits for Interrupts
      0x203 => 'aux_irq_base',          # Interrupt Vector base address
      0x400 => 'eret',                  # Exception Return Address
      0x401 => 'erbta',                 # Exception Return Branch Target Address
      0x402 => 'erstatus',              # Exception Return Status
      0x403 => 'ecr',                   # Exception Cause Register
      0x404 => 'efa',                   # Exception Fault Address
      0x40A => 'icause1',               # Level 1 Interrupt Cause Register
      0x40B => 'icause2',               # Level 2 Interrupt Cause Register
      0x40C => 'aux_ienable',           # Interrupt Mask Programming
      0x40D => 'aux_itrigger',          # Interrupt Sensitivity Programming
      0x410 => 'xpu',                   # User Mode Extension Enables
      0x412 => 'bta',                   # Branch Target Address
      0x413 => 'bta_l1',                # Level 1 Return Branch Target
      0x414 => 'bta_l2',                # Level 2 Return Branch Target
      0x415 => 'aux_irq_pulse_cancel',  # Interrupt Pulse Cancel
      0x416 => 'aux_irq_pending',       # Interrupt Pending Register
    }

    def render
      if s = Render[i]
        [s]
      else
        ["aux#@i"]
      end
    end
  end

  class Memref
    attr_accessor :base, :disp

    def initialize(base, disp, sz)
      @base, @disp, @size = base, disp, sz
    end

    def symbolic(orig)
      b = @base
      b = b.symbolic if b.kind_of? Reg

      if disp
        o = @disp
        o = o.symbolic if o.kind_of? Reg
        e = Expression[b, :+, o].reduce
      else
        e = Expression[b].reduce
      end

      Indirection[e, @size, orig]
    end

    include Renderable

    def render
      if @disp and @disp != 0
        ['[', @base, ', ', @disp, ']']
      else
        ['[', @base, ']']
      end
    end
  end
end
end
