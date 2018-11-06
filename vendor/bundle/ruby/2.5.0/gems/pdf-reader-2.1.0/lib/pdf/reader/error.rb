# coding: utf-8

################################################################################
#
# Copyright (C) 2006 Peter J Jones (pjones@pmade.com)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
class PDF::Reader
  ################################################################################
  # An internal PDF::Reader class that helps to verify various parts of the PDF file
  # are valid
  class Error # :nodoc:
    ################################################################################
    def self.str_assert(lvalue, rvalue, chars=nil)
      raise MalformedPDFError, "PDF malformed, expected string but found #{lvalue.class} instead" if chars and !lvalue.kind_of?(String)
      lvalue = lvalue[0,chars] if chars
      raise MalformedPDFError, "PDF malformed, expected '#{rvalue}' but found #{lvalue} instead"  if lvalue != rvalue
    end
    ################################################################################
    def self.str_assert_not(lvalue, rvalue, chars=nil)
      raise MalformedPDFError, "PDF malformed, expected string but found #{lvalue.class} instead" if chars and !lvalue.kind_of?(String)
      lvalue = lvalue[0,chars] if chars
      raise MalformedPDFError, "PDF malformed, expected '#{rvalue}' but found #{lvalue} instead"  if lvalue == rvalue
    end
    ################################################################################
    def self.assert_equal(lvalue, rvalue)
      raise MalformedPDFError, "PDF malformed, expected #{rvalue} but found #{lvalue} instead" if lvalue != rvalue
    end
    ################################################################################
  end

  ################################################################################
  # an exception that is raised when we believe the current PDF is not following
  # the PDF spec and cannot be recovered
  class MalformedPDFError < RuntimeError; end

  ################################################################################
  # an exception that is raised when an invalid page number is used
  class InvalidPageError < ArgumentError; end

  ################################################################################
  # an exception that is raised when a PDF object appears to be invalid
  class InvalidObjectError < MalformedPDFError; end

  ################################################################################
  # an exception that is raised when a PDF follows the specs but uses a feature
  # that we don't support just yet
  class UnsupportedFeatureError < RuntimeError; end

  ################################################################################
  # an exception that is raised when a PDF is encrypted and we don't have the
  # necessary data to decrypt it
  class EncryptedPDFError < UnsupportedFeatureError; end
end
################################################################################
