# -*- coding: binary -*-

module Msf
  # Shared helpers for Windows ARCH_AArch64 payloads (PEB/EAT ROR-13
  # hashing and the aarch64 gem assembler glue).
  module Payload::Windows::Aarch64
    #
    # ROR-13 hash of a kernel32/ws2_32 export name, matching the asm
    # find_function routine (stops on CBZ before adding the NUL).
    #
    # @param str [String] export name without trailing NUL
    # @return [Integer] 32-bit hash
    #
    def ror13_hash(str)
      h = 0
      str.each_byte do |b|
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + b) & 0xFFFFFFFF
      end
      h
    end

    #
    # Assemble an AArch64 asm string to raw bytes via the aarch64 gem.
    #
    # @param asm_string [String]
    # @return [String] raw shellcode
    #
    def compile_aarch64(asm_string)
      require 'aarch64/parser'
      parser = ::AArch64::Parser.new
      asm = parser.parse(without_inline_comments(asm_string))
      asm.to_binary
    end

    #
    # Strip `//` comments and blank lines so the aarch64 gem parser is happy.
    #
    # @param string [String]
    # @return [String]
    #
    def without_inline_comments(string)
      string.lines.map { |line| line.split('//', 2).first.strip }.reject(&:empty?).join("\n")
    end
  end
end
