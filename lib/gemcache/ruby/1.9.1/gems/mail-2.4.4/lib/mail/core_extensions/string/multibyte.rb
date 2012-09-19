# encoding: utf-8

# This is not loaded if ActiveSupport is already loaded

# This is an almost cut and paste from ActiveSupport v3.0.6, copied in here so that Mail
# itself does not depend on ActiveSupport to avoid versioning conflicts

require 'mail/multibyte'

class String
  if RUBY_VERSION >= "1.9"
    # == Multibyte proxy
    #
    # +mb_chars+ is a multibyte safe proxy for string methods.
    #
    # In Ruby 1.8 and older it creates and returns an instance of the Mail::Multibyte::Chars class which
    # encapsulates the original string. A Unicode safe version of all the String methods are defined on this proxy
    # class. If the proxy class doesn't respond to a certain method, it's forwarded to the encapsuled string.
    #
    #   name = 'Claus Müller'
    #   name.reverse # => "rell??M sualC"
    #   name.length  # => 13
    #
    #   name.mb_chars.reverse.to_s # => "rellüM sualC"
    #   name.mb_chars.length       # => 12
    #
    # In Ruby 1.9 and newer +mb_chars+ returns +self+ because String is (mostly) encoding aware. This means that
    # it becomes easy to run one version of your code on multiple Ruby versions.
    #
    # == Method chaining
    #
    # All the methods on the Chars proxy which normally return a string will return a Chars object. This allows
    # method chaining on the result of any of these methods.
    #
    #   name.mb_chars.reverse.length # => 12
    #
    # == Interoperability and configuration
    #
    # The Chars object tries to be as interchangeable with String objects as possible: sorting and comparing between
    # String and Char work like expected. The bang! methods change the internal string representation in the Chars
    # object. Interoperability problems can be resolved easily with a +to_s+ call.
    #
    # For more information about the methods defined on the Chars proxy see Mail::Multibyte::Chars. For
    # information about how to change the default Multibyte behaviour see Mail::Multibyte.
    def mb_chars
      if Mail::Multibyte.proxy_class.consumes?(self)
        Mail::Multibyte.proxy_class.new(self)
      else
        self
      end
    end

    def is_utf8? #:nodoc
      case encoding
      when Encoding::UTF_8
        valid_encoding?
      when Encoding::ASCII_8BIT, Encoding::US_ASCII
        dup.force_encoding(Encoding::UTF_8).valid_encoding?
      else
        false
      end
    end
  else
    def mb_chars
      if Mail::Multibyte.proxy_class.wants?(self)
        Mail::Multibyte.proxy_class.new(self)
      else
        self
      end
    end

    # Returns true if the string has UTF-8 semantics (a String used for purely byte resources is unlikely to have
    # them), returns false otherwise.
    def is_utf8?
      Mail::Multibyte::Chars.consumes?(self)
    end
  end
end
