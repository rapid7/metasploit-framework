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
################################################################################

class PDF::Reader
  ################################################################################
  # An internal PDF::Reader class that represents an indirect reference to a PDF Object
  class Reference
    attr_reader :id, :gen
    ################################################################################
    # Create a new Reference to an object with the specified id and revision number
    def initialize(id, gen)
      @id, @gen = id, gen
    end
    ################################################################################
    # returns the current Reference object in an array with a single element
    def to_a
      [self]
    end
    ################################################################################
    # returns the ID of this reference. Use with caution, ignores the generation id
    def to_i
      self.id
    end
    ################################################################################
    # returns true if the provided object points to the same PDF Object as the
    # current object
    def ==(obj)
      return false unless obj.kind_of?(PDF::Reader::Reference)

      self.hash == obj.hash
    end
    alias :eql? :==
    ################################################################################
    # returns a hash based on the PDF::Reference this object points to. Two
    # different Reference objects that point to the same PDF Object will
    # return an identical hash
    def hash
      "#{self.id}:#{self.gen}".hash
    end
    ################################################################################
  end
  ################################################################################
end
################################################################################
