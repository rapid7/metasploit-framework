require 'rspec'

RSpec.describe 'singles/osx/aarch64/exec' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'osx/aarch64/exec',
      ancestor_reference_names: [
        'singles/osx/aarch64/exec'
      ]
    )
  end
  let(:cmd) { nil }
  let(:datastore_values) { { 'CMD' => cmd } }

  before(:each) do
    subject.datastore.merge!(datastore_values)
  end

  describe '#create_aarch64_string_in_stack' do
    context 'when the string is calc.exe' do
      it 'generates the required stack' do
        expected = <<~'EOF'
          // Next 8 bytes of string: "CALC.EXE"
          movz x1, #0x4143 // "AC"
          movk x1, #0x434c, lsl #16 // "CL"
          movk x1, #0x452e, lsl #32 // "E."
          movk x1, #0x4558, lsl #48 // "EX"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8

          mov x1, x9 // Store the current stack location in the target register
          sub x1, x1, #8 // Update the target register to point to base of the string
        EOF
        expect(subject.create_aarch64_string_in_stack('CALC.EXE', registers: { destination: :x1, stack: :x9 })).to match_table expected
      end
    end

    context 'when the string is /bin/bash -c "echo abcdef1234"' do
      it 'generates the required stack' do
        expected = <<~'EOF'
          // Next 8 bytes of string: "/bin/bas"
          movz x1, #0x622f // "b/"
          movk x1, #0x6e69, lsl #16 // "ni"
          movk x1, #0x622f, lsl #32 // "b/"
          movk x1, #0x7361, lsl #48 // "sa"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8
          // Next 8 bytes of string: "h -c \"ec"
          movz x1, #0x2068 // " h"
          movk x1, #0x632d, lsl #16 // "c-"
          movk x1, #0x2220, lsl #32 // "\" "
          movk x1, #0x6365, lsl #48 // "ce"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8
          // Next 8 bytes of string: "ho abcde"
          movz x1, #0x6f68 // "oh"
          movk x1, #0x6120, lsl #16 // "a "
          movk x1, #0x6362, lsl #32 // "cb"
          movk x1, #0x6564, lsl #48 // "ed"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8
          // Next 8 bytes of string: "f1234\""
          movz x1, #0x3166 // "1f"
          movk x1, #0x3332, lsl #16 // "32"
          movk x1, #0x2234, lsl #32 // "\"4"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8

          mov x1, x9 // Store the current stack location in the target register
          sub x1, x1, #32 // Update the target register to point to base of the string
        EOF
        expect(subject.create_aarch64_string_in_stack('/bin/bash -c "echo abcdef1234"', registers: { destination: :x1, stack: :x9 })).to match_table expected
      end
    end
  end

  describe '#generate' do
    # Verify that the compile command is called with the expected asm string
    def expect_result_to_match(expected_asm)
      allow(subject).to receive(:compile_aarch64).and_wrap_original do |original, asm|
        expect(asm).to match_table(expected_asm)
        compiled_asm = original.call asm
        expect(compiled_asm.length).to be > 0
        'mock-aarch64-compiled'
      end
      expect(subject.generate).to eq 'mock-aarch64-compiled'
    end

    context 'when the CMD is /bin/bash' do
      let(:cmd) { '/bin/bash' }

      it 'generates the execve system call payload without arguments present' do
        expected = <<~'EOF'
          // Set system call SYS_EXECVE 0x200003b in x16
          mov x16, xzr
          movk x16, #0x0200, lsl #16
          movk x16, #0x003b

          mov x9, sp // Temporarily move SP into scratch register

          // Arg 0: execve - const char *path - Pointer to the program name to run
          // Next 8 bytes of string: "/bin/bas"
          movz x0, #0x622f // "b/"
          movk x0, #0x6e69, lsl #16 // "ni"
          movk x0, #0x622f, lsl #32 // "b/"
          movk x0, #0x7361, lsl #48 // "sa"
          str x0, [x9], #8 // Store x0 on x9-stack and increment by 8
          // Next 8 bytes of string: "h\x00"
          movz x0, #0x0068 // "\x00h"
          str x0, [x9], #8 // Store x0 on x9-stack and increment by 8

          mov x0, x9 // Store the current stack location in the target register
          sub x0, x0, #16 // Update the target register to point to base of the string



          // Push execve arguments, using x1 as a temporary register


          // Arg 1: execve - char *const argv[] - program arguments
          // argv[0] = create pointer to base of string value "/bin/bash\x00"
          mov x1, x9
          sub x1, x1, #16 // Update the target register to point to base of the string
          str x1, [x9], #8 // Store the pointer in the stack


          // argv[1] = NULL
          str xzr, [x9], #8

          // Set execve arg1 to the base of the argv array of pointers
          mov x1, x9
          sub x1, x1, #16

          // Arg 2: execve - char *const envp[] - Environment variables, NULL for now
          mov x2, xzr
          // System call
          svc #0
        EOF

        expect_result_to_match(expected)
      end
    end

    context 'when the CMD is /bin/bash -c "echo abc"' do
      let(:cmd) { '/bin/bash -c "echo abc"' }

      it 'generates the exece system call payload with arguments present' do
        expected = <<~'EOF'
          // Set system call SYS_EXECVE 0x200003b in x16
          mov x16, xzr
          movk x16, #0x0200, lsl #16
          movk x16, #0x003b

          mov x9, sp // Temporarily move SP into scratch register

          // Arg 0: execve - const char *path - Pointer to the program name to run
          // Next 8 bytes of string: "/bin/bas"
          movz x0, #0x622f // "b/"
          movk x0, #0x6e69, lsl #16 // "ni"
          movk x0, #0x622f, lsl #32 // "b/"
          movk x0, #0x7361, lsl #48 // "sa"
          str x0, [x9], #8 // Store x0 on x9-stack and increment by 8
          // Next 8 bytes of string: "h\x00"
          movz x0, #0x0068 // "\x00h"
          str x0, [x9], #8 // Store x0 on x9-stack and increment by 8

          mov x0, x9 // Store the current stack location in the target register
          sub x0, x0, #16 // Update the target register to point to base of the string



          // Push execve arguments, using x1 as a temporary register
          // Push argument 0
          // Next 8 bytes of string: "-c\x00"
          movz x1, #0x632d // "c-"
          movk x1, #0x00, lsl #16 // "\x00"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8

          mov x1, x9 // Store the current stack location in the target register
          sub x1, x1, #8 // Update the target register to point to base of the string


          // Push argument 1
          // Next 8 bytes of string: "echo abc"
          movz x1, #0x6365 // "ce"
          movk x1, #0x6f68, lsl #16 // "oh"
          movk x1, #0x6120, lsl #32 // "a "
          movk x1, #0x6362, lsl #48 // "cb"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8
          // Next 8 bytes of string: "\x00"
          movz x1, #0x00 // "\x00"
          str x1, [x9], #8 // Store x1 on x9-stack and increment by 8

          mov x1, x9 // Store the current stack location in the target register
          sub x1, x1, #16 // Update the target register to point to base of the string



          // Arg 1: execve - char *const argv[] - program arguments
          // argv[0] = create pointer to base of string value "/bin/bash\x00"
          mov x1, x9
          sub x1, x1, #40 // Update the target register to point to base of the string
          str x1, [x9], #8 // Store the pointer in the stack

          // argv[1] = create pointer to base of string value "-c\x00"
          mov x1, x9
          sub x1, x1, #32 // Update the target register to point to base of the string
          str x1, [x9], #8 // Store the pointer in the stack

          // argv[2] = create pointer to base of string value "echo abc\x00"
          mov x1, x9
          sub x1, x1, #32 // Update the target register to point to base of the string
          str x1, [x9], #8 // Store the pointer in the stack


          // argv[3] = NULL
          str xzr, [x9], #8

          // Set execve arg1 to the base of the argv array of pointers
          mov x1, x9
          sub x1, x1, #32

          // Arg 2: execve - char *const envp[] - Environment variables, NULL for now
          mov x2, xzr
          // System call
          svc #0
        EOF
        expect_result_to_match(expected)
      end
    end
  end
end
