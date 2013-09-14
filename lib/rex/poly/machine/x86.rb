
module Rex

  module Poly

    #
    # A subclass to represent a Rex poly machine on the x86 architecture.
    #
    class MachineX86 < Rex::Poly::Machine

      def initialize( badchars='', consume_base_pointer=nil, consume_stack_pointer=true )
        super( badchars, Metasm::Ia32.new )

        @reg_available << Rex::Arch::X86::EAX
        @reg_available << Rex::Arch::X86::EBX
        @reg_available << Rex::Arch::X86::ECX
        @reg_available << Rex::Arch::X86::EDX
        @reg_available << Rex::Arch::X86::ESI
        @reg_available << Rex::Arch::X86::EDI
        @reg_available << Rex::Arch::X86::EBP
        @reg_available << Rex::Arch::X86::ESP

        # By default we consume the EBP register if badchars contains \x00. This helps speed
        # things up greatly as many instructions opperating on EBP introduce a NULL byte. For
        # example, a MOV instruction with EAX as the source operand is as follows:
        #     8B08    mov ecx, [eax]
        # but the same instruction with EBP as the source operand is as follows:
        #     8B4D00  mov ecx, [ebp] ; This is assembled as 'mov ecx, [ebp+0]'
        # we can see that EBP is encoded differently with an offset included. We can still
        # try to generate a solution with EBP included and \x00 in the badchars list but
        # it can take considerably longer.
        if( ( consume_base_pointer.nil? and not Rex::Text.badchar_index( "\x00", @badchars ).nil? ) or consume_base_pointer == true )
          create_variable( 'base_pointer', 'ebp' )
        end

        # By default we consume the ESP register to avoid munging the stack.
        if( consume_stack_pointer )
          create_variable( 'stack_pointer', 'esp' )
        end

        # discover all the safe FPU instruction we can use.
        @safe_fpu_instructions = ::Array.new
        Rex::Arch::X86.fpu_instructions.each do | fpu |
          if( is_valid?( fpu ) )
            @safe_fpu_instructions << fpu
          end
        end
      end

      #
      # The general purpose registers are 32bit
      #
      def native_size
        Rex::Poly::Machine::DWORD
      end

      #
      # Overload this method to intercept the 'set' primitive with the 'location' keyword
      # and create the block with the '_set_variable_location'. We do this to keep a
      # consistent style.
      #
      def create_block_primitive( block_name, primitive_name, *args )
        if( primitive_name == 'set' and args.length == 2 and args[1] == 'location' )
          _create_block_primitive( block_name, '_set_variable_location', args[0] )
        else
          super
        end
      end

      #
      # XXX: If we have a loop primitive, it is a decent speed bump to force the associated variable
      # of the first loop primitive to be assigned as ECX (for the x86 LOOP instruction), this is not
      # neccasary but can speed generation up significantly.
      #
      #def generate
      #	@blocks.each_value do | block |
      #		if( block.first.primitive == 'loop' )
      #			@variables.delete( block.first.args.first )
      #			create_variable( block.first.args.first, 'ecx' )
      #			break
      #		end
      #	end
      #	# ...go go go
      #	super
      #end

      protected

      #
      # Resolve a register number into a suitable register name.
      #
      def _register_value( regnum, size=nil )
        value = nil
        # we default to a native 32 bits if no size is specified.
        if( size.nil? )
          size = native_size()
        end

        if( size == Rex::Poly::Machine::DWORD )
          value = Rex::Arch::X86::REG_NAMES32[ regnum ]
        elsif( size == Rex::Poly::Machine::WORD )
          value = Rex::Arch::X86::REG_NAMES16[ regnum ]
        elsif( size == Rex::Poly::Machine::BYTE )
          # (will return nil for ESI,EDI,EBP,ESP)
          value = Rex::Arch::X86::REG_NAMES8L[ regnum ]
        else
          raise RuntimeError, "Register number '#{regnum}' (size #{size.to_i}) is unavailable."
        end
        return value
      end

      #
      # Create the x86 primitives.
      #
      def _create_primitives

        #
        # Create the '_set_variable_location' primitive. The first param it the variable to place the current
        # blocks location value in.
        #
        _create_primitive( '_set_variable_location',
          ::Proc.new do | block, machine, variable |
            if( @safe_fpu_instructions.empty? )
              raise UnallowedPermutation
            end
            [
              "dw #{ "0x%04X" % [ @safe_fpu_instructions[ rand(@safe_fpu_instructions.length) ].unpack( 'v' ).first ] }",
              "mov #{machine.variable_value( 'temp' )}, esp",
              "fnstenv [ #{machine.variable_value( 'temp' )} - 12 ]",
              "pop #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable |
            if( @safe_fpu_instructions.empty? )
              raise UnallowedPermutation
            end
            [
              "dw #{ "0x%04X" % [ @safe_fpu_instructions[ rand(@safe_fpu_instructions.length) ].unpack( 'v' ).first ] }",
              "mov #{machine.variable_value( 'temp' )}, esp",
              "fnstenv [ #{machine.variable_value( 'temp' )} - 12 ]",
              "pop #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable |
            if( @safe_fpu_instructions.empty? )
              raise UnallowedPermutation
            end
            [
              "dw #{ "0x%04X" % [ @safe_fpu_instructions[ rand(@safe_fpu_instructions.length) ].unpack( 'v' ).first ] }",
              "push esp",
              "pop #{machine.variable_value( 'temp' )}",
              "fnstenv [ #{machine.variable_value( 'temp' )} - 12 ]",
              "pop #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable |
            if( @safe_fpu_instructions.empty? )
              raise UnallowedPermutation
            end
            [
              "dw #{ "0x%04X" % [ @safe_fpu_instructions[ rand(@safe_fpu_instructions.length) ].unpack( 'v' ).first ] }",
              "fnstenv [ esp - 12 ]",
              "pop #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable |
            [
              "call $+5",
              "pop #{machine.variable_value( variable )}",
              "push #{machine.block_offset( block ) + 5}",
              "pop #{machine.variable_value( 'temp' )}",
              "sub #{machine.variable_value( variable )}, #{machine.variable_value( 'temp' )}"
            ]
          end,
          ::Proc.new do | block, machine, variable |
            [
              "db 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0",
              "pop #{machine.variable_value( variable )}",
              "push #{machine.block_offset( block ) + 5}",
              "pop #{machine.variable_value( 'temp' )}",
              "sub #{machine.variable_value( variable )}, #{machine.variable_value( 'temp' )}"
            ]
          end
        )

        #
        # Create the 'loop' primitive. The first param it the counter variable which holds the number of
        # times to perform the loop. The second param it the destination block to loop to.
        #
        _create_primitive( 'loop',
          ::Proc.new do | block, machine, counter, destination |
            if( machine.variable_value( counter ) != Rex::Arch::X86::REG_NAMES32[ Rex::Arch::X86::ECX ] )
              # we raise and UndefinedPermutation exception to indicate that untill a valid register (ECX) is
              # chosen we simply can't render this. This lets the machine know we can still try to use this
              # permutation and at a later stage the requirements (counter==ecx) may be satisfied.
              raise UndefinedPermutation
            end
            offset = -( machine.block_offset( machine.block_next( block ) ) - machine.block_offset( destination ) )
            Rex::Arch::X86.loop( offset )
          end,
          ::Proc.new do | block, machine, counter, destination |
            offset = -( machine.block_offset( machine.block_next( block ) ) - machine.block_offset( destination ) )
            [
              "dec #{machine.variable_value( counter )}",
              "test #{machine.variable_value( counter )}, #{machine.variable_value( counter )}",
              # JNZ destination
              "db 0x0F, 0x85 dd #{ "0x%08X" % [ offset & 0xFFFFFFFF ] }"
            ]
          end
        )

        #
        # Create the 'xor' primitive. The first param it the variable to xor with the second param value which
        # can be either a variable, literal or block offset.
        #
        _create_primitive( 'xor',
          ::Proc.new do | block, machine, variable, value |
            [
              "xor #{machine.variable_value( variable )}, #{machine.resolve_value( value )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            # a ^ b == (a | b) & ~(a & b)
            [
              "mov #{machine.variable_value( 'temp' )}, #{machine.variable_value( variable )}",
              "or #{machine.variable_value( 'temp' )}, #{machine.resolve_value( value )}",
              "and #{machine.variable_value( variable )}, #{machine.resolve_value( value )}",
              "not #{machine.variable_value( variable )}",
              "and #{machine.variable_value( variable )}, #{machine.variable_value( 'temp' )}"
            ]
          end
        )

        #
        # Create the 'goto' primitive. The first param is a destination block to jump to.
        #
        _create_primitive( 'goto',
          ::Proc.new do | block, machine, destination |
            offset = -( machine.block_offset( machine.block_next( block ) ) - machine.block_offset( destination ) )
            if( ( offset > 0 and offset > 127 ) or ( offset < 0 and offset < -127 ) )
              raise UnallowedPermutation
            end
            [
              # short relative jump
              "db 0xEB db #{ "0x%02X" % [ offset & 0xFF ] }"
            ]
          end,
          ::Proc.new do | block, machine, destination |
            offset = -( machine.block_offset( machine.block_next( block ) ) - machine.block_offset( destination ) )
            [
              # near relative jump
              "db 0xE9 dd #{ "0x%08X" % [ offset & 0xFFFFFFFF ] }"
            ]
          end
        )

        #
        # Create the 'add' primitive. The first param it the variable which will be added to the second
        # param, which may either be a literal number value, a variables assigned register or a block
        # name, in which case the block offset will be used.
        #
        _create_primitive( 'add',
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            [
              "lea #{machine.variable_value( variable )}, [ #{machine.variable_value( variable )} + #{machine.resolve_value( value )} ]"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            [
              "push #{machine.resolve_value( value )}",
              "add #{machine.variable_value( variable )}, [esp]",
              "pop #{machine.variable_value( 'temp' )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            [
              "add #{machine.variable_value( variable )}, #{machine.resolve_value( value )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            [
              "sub #{machine.variable_value( variable )}, #{ "0x%08X" % [ ~(machine.resolve_value( value ) - 1) & 0xFFFFFFFF ] }"
            ]
          end
          # ::Proc.new do | block, machine, variable, value |
            # if( machine.variable_exist?( value ) )
            #	raise UnallowedPermutation
            # end
            # [
              # "push #{ "0x%08X" % [ ~(machine.resolve_value( value ) - 1) & 0xFFFFFFFF ] }",
              # "pop #{machine.variable_value( 'temp' )}",
              # "not #{machine.variable_value( 'temp' )}",
              # "add #{machine.variable_value( variable )}, #{machine.variable_value( 'temp' )}"
            # ]
          # end,
          # ::Proc.new do | block, machine, variable, value |
            # if( machine.variable_exist?( value ) )
            #	raise UnallowedPermutation
            # end
            # [
              # "xor #{machine.variable_value( 'temp' )}, #{machine.variable_value( 'temp' )}",
              # "mov #{machine.variable_value( 'temp', 16 )}, #{ "0x%04X" % [ ~(machine.resolve_value( value ) - 1) & 0xFFFF ] }",
              # "not #{machine.variable_value( 'temp', 16 )}",
              # "add #{machine.variable_value( variable )}, #{machine.variable_value( 'temp' )}"
            # ]
          # end,
        )

        #
        # Create the 'set' primitive. The first param it the variable which will be set. the second
        # param is the value to set the variable to (a variable, block or literal).
        #
        _create_primitive( 'set',
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            [
              "push #{ "0x%08X" % [ ~machine.resolve_value( value ) & 0xFFFFFFFF ] }",
              "pop #{machine.variable_value( variable )}",
              "not #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            if( machine.resolve_value( value, WORD ) > 0xFFFF )
              raise UndefinedPermutation
            end
            [
              "xor #{machine.variable_value( variable )}, #{machine.variable_value( variable )}",
              "mov #{machine.variable_value( variable, WORD )}, #{ "0x%04X" % [ ~machine.resolve_value( value, WORD ) & 0xFFFF ] }",
              "not #{machine.variable_value( variable, WORD )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            [
              "push #{machine.resolve_value( value )}",
              "pop #{machine.variable_value( variable )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            [
              "mov #{machine.variable_value( variable )}, #{machine.resolve_value( value )}"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            if( machine.resolve_value( value, WORD ) > 0xFFFF )
              raise UndefinedPermutation
            end
            [
              "xor #{machine.variable_value( variable )}, #{machine.variable_value( variable )}",
              "mov #{machine.variable_value( variable, WORD )}, #{ "0x%04X" % [ machine.resolve_value( value, WORD ) & 0xFFFF ] }"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            dword = machine.make_safe_dword( machine.resolve_value( value ) )
            [
              "mov #{machine.variable_value( variable )}, #{ "0x%08X" % [ dword ] }",
              "sub #{machine.variable_value( variable )}, #{ "0x%08X" % [ dword - machine.resolve_value( value ) ] }"
            ]
          end,
          ::Proc.new do | block, machine, variable, value |
            if( machine.variable_exist?( value ) )
              raise UnallowedPermutation
            end
            dword = machine.make_safe_dword( machine.resolve_value( value ) )
            [
              "mov #{machine.variable_value( variable )}, #{ "0x%08X" % [ dword - machine.resolve_value( value ) ] }",
              "add #{machine.variable_value( variable )}, #{ "0x%08X" % [ ~dword & 0xFFFFFFFF ] }",
              "not #{machine.variable_value( variable )}"
            ]
          end
        )

        #
        # Create the 'load' primitive. The first param it the variable which will be set. The second
        # param is the value (either a variable or literal) to load from. the third param is the size
        # of the load operation, either DWORD, WORD or BYTE.
        #
        _create_primitive( 'load',
          ::Proc.new do | block, machine, variable, value, size |
            result = nil
            if( size == Rex::Poly::Machine::DWORD )
              result = [ "mov #{machine.variable_value( variable )}, [#{machine.resolve_value( value )}]" ]
            elsif( size == Rex::Poly::Machine::WORD )
              result = [ "movzx #{machine.variable_value( variable )}, word [#{machine.resolve_value( value )}]" ]
            elsif( size == Rex::Poly::Machine::BYTE )
              result = [ "movzx #{machine.variable_value( variable )}, byte [#{machine.resolve_value( value )}]" ]
            else
              raise InvalidPermutation
            end
            result
          end,
          ::Proc.new do | block, machine, variable, value, size |
            result = nil
            if( size == Rex::Poly::Machine::DWORD )
              # we raise and UnallowedPermutation here as this permutation should only satisfy requests for
              # sizes of WORD or BYTE, any DWORD requests will be satisfied by the above permutation (otherwise
              # we would just be duplicating a 'mov dest, [src]' sequence which is the same as above.
              raise UnallowedPermutation
            elsif( size == Rex::Poly::Machine::WORD )
              result = [
                "mov #{machine.variable_value( variable )}, [#{machine.resolve_value( value )}]",
                "shl #{machine.variable_value( variable )}, 16",
                "shr #{machine.variable_value( variable )}, 16"
              ]
            elsif( size == Rex::Poly::Machine::BYTE )
              result = [
                "mov #{machine.variable_value( variable )}, [#{machine.resolve_value( value )}]",
                "shl #{machine.variable_value( variable )}, 24",
                "shr #{machine.variable_value( variable )}, 24"
              ]
            else
              raise InvalidPermutation
            end
            result
          end,
          ::Proc.new do | block, machine, variable, value, size |
            result = nil
            if( size == Rex::Poly::Machine::DWORD )
              result = [
                "push [#{machine.resolve_value( value )}]",
                "pop #{machine.variable_value( variable )}"
              ]
            elsif( size == Rex::Poly::Machine::WORD )
              result = [
                "push [#{machine.resolve_value( value )}]",
                "pop #{machine.variable_value( variable )}",
                "shl #{machine.variable_value( variable )}, 16",
                "shr #{machine.variable_value( variable )}, 16"
              ]
            elsif( size == Rex::Poly::Machine::BYTE )
              result = [
                "push [#{machine.resolve_value( value )}]",
                "pop #{machine.variable_value( variable )}",
                "shl #{machine.variable_value( variable )}, 24",
                "shr #{machine.variable_value( variable )}, 24"
              ]
            else
              raise InvalidPermutation
            end
            result
          end
        )

        #
        # Create the 'store' primitive.
        #
        _create_primitive( 'store',
          ::Proc.new do | block, machine, variable, value, size |
            result = nil
            if( size == Rex::Poly::Machine::DWORD )
              result = [ "mov [#{machine.variable_value( variable )}], #{machine.resolve_value( value )}" ]
            elsif( size == Rex::Poly::Machine::WORD )
              result = [ "mov word [#{machine.variable_value( variable )}], #{machine.resolve_value( value, WORD )}" ]
            elsif( size == Rex::Poly::Machine::BYTE )
              if( machine.resolve_value( value, BYTE ).nil? )
                # so long as we cant resolve the variable to an 8bit register value (AL,BL,CL,DL) we must raise
                # an UndefinedPermutation exception (this will happen when the variable has been assigned to ESI,
                # EDI, EBP or ESP which dont have a low byte representation)
                raise UndefinedPermutation
              end
              result = [ "mov byte [#{machine.variable_value( variable )}], #{machine.resolve_value( value, BYTE )}" ]
            else
              raise InvalidPermutation
            end
            result
          end,
          ::Proc.new do | block, machine, variable, value, size |
            result = nil
            if( size == Rex::Poly::Machine::DWORD )
              result = [
                "push #{machine.resolve_value( value )}",
                "pop [#{machine.variable_value( variable )}]"
              ]
            elsif( size == Rex::Poly::Machine::WORD )
              result = [
                "push #{machine.resolve_value( value, WORD )}",
                "pop word [#{machine.variable_value( variable )}]"
              ]
            else
              # we can never do this permutation for BYTE size (or any other size)
              raise UnallowedPermutation
            end
            result
          end
        )
      end

    end

  end

end
