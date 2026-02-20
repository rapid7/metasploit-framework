module Metasploit::Framework::Obfuscation
    DEBUG = false
    class AssemblyObfuscator

        template_matrix = {:instructions => [], :rules => [''], :custom_rule => nil}

        module CommonRules
            def self.register_operand(operand)
                all_registers = %w[rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15 eax ebx ecx edx esi edi esp ebp]
                all_registers.include?(operand.downcase)
            end

            def self.immediate_value_below_32bit(operand)
                if operand.start_with?('0x')
                    value = operand.to_i(16)
                else
                    value = operand.to_i
                end
                value >= 0 && value <= 0xFFFFFFFF
            end
        end

        def initialize(assembly_code, arch: 'x64', percentual: 50)
            @assembly_code = assembly_code
            @arch = arch
            @percentual = percentual
            @temp_registers = get_arch_registers.dup
            @obfuscation_matrix = {
                'mov' => [
                    {
                        :instructions => ['xor {dest}, {dest}', 'add {dest}, {src}'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure dest is a register, src != dest (xor dest,dest zeros it),
                            # and src is a register or immediate value below 32-bit
                            src = operands[:src]
                            dest = operands[:dst]
                            return false unless dest && CommonRules.register_operand(dest)
                            return false if src && dest && src.downcase == dest.downcase
                            return true if CommonRules.register_operand(src)
                            return true if CommonRules.immediate_value_below_32bit(src)
                            false
                        }
                    },
                    {
                        :instructions => ['push {src}', 'pop {dest}'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure src and dest are registers
                            src = operands[:src]
                            dest = operands[:dst]
                            return false unless CommonRules.register_operand(src)
                            return false unless CommonRules.register_operand(dest)
                            true
                        }
                    },
                    {
                        :instructions => ['sub {dest}, {dest}', 'or {dest}, {src}'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure dest is a register, src != dest, and src is register or immediate
                            src = operands[:src]
                            dest = operands[:dst]
                            return false unless dest && CommonRules.register_operand(dest)
                            return false if src && dest && src.downcase == dest.downcase
                            return true if CommonRules.register_operand(src)
                            return true if CommonRules.immediate_value_below_32bit(src)
                            false
                        }
                    },
                    {
                        :instructions => ['lea {dest}, [{src}]'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure both src and dest are registers (lea reg-to-reg only)
                            src = operands[:src]
                            dest = operands[:dst]
                            return false unless src && CommonRules.register_operand(src)
                            return false unless dest && CommonRules.register_operand(dest)
                            true
                        }
                    }
                ],
                'add' => [
                    {
                        :instructions => ['inc {dest}', 'add {dest}, {src}', 'dec {dest}'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure src is register or immediate value below 32-bit
                            src = operands[:src]
                            return true if CommonRules.register_operand(src)
                            return true if CommonRules.immediate_value_below_32bit(src)
                            false
                        } 
                    },
                    {
                        :instructions => ['sub {dest}, {random}', 'add {dest}, {src}', 'add {dest}, {random}'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'sub' => [
                    {
                        :instructions => ['dec {dest}', 'sub {dest}, {src}', 'inc {dest}'],
                        :rules => [],
                        :custom_rule => lambda { |operands|
                            # ensure src is register or immediate value below 32-bit
                            src = operands[:src]
                            return true if CommonRules.register_operand(src)
                            return true if CommonRules.immediate_value_below_32bit(src)
                            false
                        } 
                    },
                    {
                        :instructions => ['add {dest}, {random}', 'sub {dest}, {src}', 'sub {dest}, {random}'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'push' => [
                    {
                        :instructions => ['sub {sp}, {arch_val}', 'mov [{sp}], {src}'],
                        :rules => ['{src} == {reg}'],
                        :custom_rule => nil
                    },
                ],
                'pop' => [
                    {
                        :instructions => ['mov {dest}, [{sp}]', 'add {sp}, {arch_val}'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    },
                ],
                'xchg' => [
                    {
                        :instructions => ['push {dest}', 'mov {dest}, {src}', 'pop {src}'],
                        :rules => ['{src} == {reg}', '{dest} == {reg}'],
                        :custom_rule => nil
                    },
                    {
                        :instructions => ['xor {dest}, {src}', 'xor {src}, {dest}', 'xor {dest}, {src}'],
                        :rules => ['{src} == {reg}', '{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'inc' => [
                    {
                        :instructions => ['add {dest}, 1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    },
                    {
                        :instructions => ['sub {dest}, {random}', 'add {dest}, {random}', 'add {dest}, 1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'dec' => [
                    {
                        :instructions => ['sub {dest}, 1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    },
                    {
                        :instructions => ['add {dest}, {random}', 'sub {dest}, 1', 'sub {dest}, {random}'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'neg' => [
                    {
                        :instructions => ['xor {dest}, -1', 'add {dest}, 1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
                'not' => [
                    {
                        :instructions => ['xor {dest}, -1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    },
                    {
                        :instructions => ['neg {dest}', 'sub {dest}, 1'],
                        :rules => ['{dest} == {reg}'],
                        :custom_rule => nil
                    }
                ],
            }
        end

        def get_arch_registers
            if @arch == 'x64'
                %w[rax rbx rcx rdx rsi rdi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15]
            else
                %w[eax ebx ecx edx esi edi esp ebp]
            end
        end

        def is_register?(operand)
            puts "DEBUG: Checking if operand '#{operand}' is a register 1" if DEBUG
            all_registers = get_arch_registers
            all_registers.include?(operand.downcase)
        end

        def source_and_destination_operands(line)
            mnemonic, *operands = line.strip.split
            src = nil
            dest = nil
            if operands.size == 2
                src = operands[1]
                dest = operands[0].chomp(',')
            elsif operands.size == 1
                if mnemonic == 'push'
                    src = operands[0]
                elsif ['pop', 'inc', 'dec', 'neg', 'not'].include?(mnemonic)
                    dest = operands[0]
                end
            end
            { src: src, dst: dest }
        end
        def avaiable_temp_registers(assembly_code, exclude_regs = [])
            all_registers = get_arch_registers
            used_registers = []
            assembly_code.lines.each do |line|
                tokens = line.strip.split
                next if tokens.empty?
                mnemonic = tokens[0]
                operands = tokens[1..-1].join(' ').split(',').map(&:strip)
                operands.each do |op|
                    if is_register?(op) && !used_registers.include?(op) && !exclude_regs.include?(op)
                        used_registers << op
                    end
                end
            end
            temp_registers = all_registers - used_registers - exclude_regs
            temp_registers
        end

        def is_immediate_value?(operand)
            immediate_value_regex = /^(0x[0-9a-fA-F]+|\d+)$/
            !!(operand =~ immediate_value_regex)
        end

        def is_register_operand?(operand)
            is_register?(operand) || operand.start_with?('[') && operand.end_with?(']') && is_register?(operand[1..-2])
        end

        def rule_validate_placeholder(rule, operands)
            case rule
            when '{src} == {reg}'
                src = operands[:src]
                return is_register_operand?(src)
            when '{dest} == {reg}'
                dest = operands[:dst]
                return is_register_operand?(dest)
            when '{src} == {imm}'
                src = operands[:src]
                return is_immediate_value?(src)
            when '{dest} == {imm}'
                dest = operands[:dst]
                return is_immediate_value?(dest)
            when '$or'
                sub_rules = rule['$or']
                return sub_rules.any? { |sub_rule| rule_validate_placeholder(sub_rule, operands) }
            when '$and'
                sub_rules = rule['$and']
                return sub_rules.all? { |sub_rule| rule_validate_placeholder(sub_rule, operands) }
            else
                return true
            end
        end
        def validate_obfuscation_rule(rule, operands)
            return rule_validate_placeholder(rule, operands) if rule.is_a?(String)
            false
        end

        def validate_obfuscation_rules(rules, operands, custom_rule = nil)
            is_valid = true
            rules.each do |rule|
                is_valid = validate_obfuscation_rule(rule, operands)
                break unless is_valid
            end
            if is_valid && custom_rule
                is_valid = custom_rule.call(operands)
            end
            is_valid
        end

        def get_avaiable_obfuscations_for_line(line)
            mnemonic, *operands = line.strip.split
            operands_hash = source_and_destination_operands(line)
            valid_obfuscations = []
            possible_obfuscations = @obfuscation_matrix[mnemonic]
            return [] if possible_obfuscations.nil? || possible_obfuscations.empty?
            possible_obfuscations.each do |obf|
                rules = obf[:rules] || []
                custom_rule = obf[:custom_rule] || nil
                if validate_obfuscation_rules(rules, operands_hash, custom_rule)
                    puts "DEBUG: Valid obfuscation found for line '#{line.strip}': #{obf[:instructions].join(' | ')}" if DEBUG
                    valid_obfuscations << obf
                end
            end
            valid_obfuscations
        end


        def get_sp
            @arch == 'x64' ? 'rsp' : 'esp'
        end


        def obfuscate_line(line, obfuscation)
            obfuscated_line_output = []
            mnemonic = line.split.first
            operands = source_and_destination_operands(line)
            sp = get_sp
            random_value = rand(1..100)
            obfuscation[:instructions].each do |instr|
                random_instr = instr.dup
                random_instr = random_instr.split(';').first.strip
                random_instr.gsub!('{src}', operands[:src].to_s) if operands[:src]
                random_instr.gsub!('{dest}', operands[:dst].to_s) if operands[:dst]
                random_instr.gsub!('{sp}', sp)
                random_instr.gsub!('{arch_val}', @arch == 'x64' ? '8' : '4')
                random_instr.gsub!('{random}', random_value.to_s)
                obfuscated_line_output << random_instr + "\n"
                puts "DEBUG: Generated obfuscated instruction: #{random_instr}" if DEBUG
            end
            obfuscated_line_output
        end

        def obfuscate_once(code)
            result_lines = []
            lines = code.lines if code.is_a?(String)
            lines = code if code.is_a?(Array)

            lines.map do |line|
                # remove multiple spaces
                line = line.gsub(/\s+/, ' ').strip
                line = line.gsub(/\t+/, ' ').strip
                line = line.split(';').first.strip if line.include?(';')
                next if line.empty?
                line += "\n" unless line.end_with?("\n")

                puts "DEBUG: Processing line: #{line.strip}" if DEBUG
                possible_obfuscations = get_avaiable_obfuscations_for_line(line)
                if !possible_obfuscations.empty? && rand(100) < @percentual
                    random_obfuscation = possible_obfuscations.sample
                    puts "DEBUG: Obfuscating line: #{line.strip}" if DEBUG
                    obfuscated_lines = obfuscate_line(line, random_obfuscation)
                    # puts "DEBUG: Obfuscating line: #{line.strip} -> #{obfuscated_lines.map(&:strip).join(' | ')}" if DEBUG
                else
                    puts "DEBUG: Skipping line: #{line.strip}" if DEBUG
                    obfuscated_lines = [line]
                end

                # append obfuscated lines to result
                result_lines.concat(obfuscated_lines)
            end
            puts "DEBUG: Resulting lines: #{result_lines}}" if DEBUG
            result_lines.flatten.join
        end

        def obfuscate(passes = 1)
            obfuscated_code = @assembly_code.dup
            for pass in 1..passes
                puts "Executing pass number #{pass}..." if DEBUG
                obfuscated_code = obfuscate_once(obfuscated_code)
                puts "DEBUG: Obfuscated code after pass #{pass}:\n#{obfuscated_code}" if DEBUG
            end
            obfuscated_code
        end
    end
end