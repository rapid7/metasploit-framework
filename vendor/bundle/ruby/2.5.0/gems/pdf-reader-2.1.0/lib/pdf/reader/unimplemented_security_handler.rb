# coding: utf-8

class PDF::Reader

  # Security handler for when we don't support the flavour of encryption
  # used in a PDF.
  class UnimplementedSecurityHandler
    def self.supports?(encrypt)
      true
    end

    def decrypt(buf, ref)
      raise PDF::Reader::EncryptedPDFError, "Unsupported encryption style"
    end
  end
end
