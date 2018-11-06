# coding: utf-8

class PDF::Reader
  # co-ordinate systems in PDF files are specified using a 3x3 matrix that looks
  # something like this:
  #
  #   [ a b 0 ]
  #   [ c d 0 ]
  #   [ e f 1 ]
  #
  # Because the final column never changes, we can represent each matrix using
  # only 6 numbers. This is important to save CPU time, memory and GC pressure
  # caused by allocating too many unnecessary objects.
  class TransformationMatrix
    attr_reader :a, :b, :c, :d, :e, :f

    def initialize(a, b, c, d, e, f)
      @a, @b, @c, @d, @e, @f = a, b, c, d, e, f
    end

    def inspect
      "#{a}, #{b}, 0,\n#{c}, #{d}, #{0},\n#{e}, #{f}, 1"
    end

    def to_a
      [@a,@b,0,
       @c,@d,0,
       @e,@f,1]
    end

    # multiply this matrix with another.
    #
    # the second matrix is represented by the 6 scalar values that are changeable
    # in a PDF transformation matrix.
    #
    # WARNING: This mutates the current matrix to avoid allocating memory when
    #          we don't need too. Matrices are multiplied ALL THE FREAKING TIME
    #          so this is a worthwhile optimisation
    #
    # NOTE: When multiplying matrices, ordering matters. Double check
    #       the PDF spec to ensure you're multiplying things correctly.
    #
    # NOTE: see Section 8.3.3, PDF 32000-1:2008, pp 119
    #
    # NOTE: The if statements in this method are ordered to prefer optimisations
    #       that allocate fewer objects
    #
    # TODO: it might be worth adding an optimised path for vertical
    #       displacement to speed up processing documents that use vertical
    #       writing systems
    #
    def multiply!(a,b=nil,c=nil, d=nil,e=nil,f=nil)
      if a == 1 && b == 0 && c == 0 && d == 1 && e == 0 && f == 0
        # the identity matrix, no effect
        self
      elsif @a == 1 && @b == 0 && @c == 0 && @d == 1 && @e == 0 && @f == 0
        # I'm the identity matrix, so just copy values across
        @a = a
        @b = b
        @c = c
        @d = d
        @e = e
        @f = f
      elsif a == 1 && b == 0 && c == 0 && d == 1 && f == 0
        # the other matrix is a horizontal displacement
        horizontal_displacement_multiply!(e)
      elsif @a == 1 && @b == 0 && @c == 0 && @d == 1 && @f == 0
        # I'm a horizontal displacement
        horizontal_displacement_multiply_reversed!(a,b,c,d,e,f)
      elsif @a != 1 && @b == 0 && @c == 0 && @d != 1 && @e == 0 && @f == 0
        # I'm a xy scale
        xy_scaling_multiply_reversed!(a,b,c,d,e,f)
      elsif a != 1 && b == 0 && c == 0 && d != 1 && e == 0 && f == 0
        # the other matrix is an xy scale
        xy_scaling_multiply!(a,b,c,d,e,f)
      else
        faster_multiply!(a,b,c, d,e,f)
      end
      self
    end

    # Optimised method for when the second matrix in the calculation is
    # a simple horizontal displacement.
    #
    # Like this:
    #
    #   [ 1 2 0 ]   [ 1  0 0 ]
    #   [ 3 4 0 ] x [ 0  1 0 ]
    #   [ 5 6 1 ]   [ e2 0 1 ]
    #
    def horizontal_displacement_multiply!(e2)
      @e = @e + e2
    end

    private

    # Optimised method for when the first matrix in the calculation is
    # a simple horizontal displacement.
    #
    # Like this:
    #
    #   [ 1 0 0 ]   [ 1 2 0 ]
    #   [ 0 1 0 ] x [ 3 4 0 ]
    #   [ 5 0 1 ]   [ 5 6 1 ]
    #
    def horizontal_displacement_multiply_reversed!(a2,b2,c2,d2,e2,f2)
      newa = a2
      newb = b2
      newc = c2
      newd = d2
      newe = (@e * a2) + e2
      newf = (@e * b2) + f2
      @a, @b, @c, @d, @e, @f = newa, newb, newc, newd, newe, newf
    end

    # Optimised method for when the second matrix in the calculation is
    # an X and Y scale
    #
    # Like this:
    #
    #   [ 1 2 0 ]   [ 5 0 0 ]
    #   [ 3 4 0 ] x [ 0 5 0 ]
    #   [ 5 6 1 ]   [ 0 0 1 ]
    #
    def xy_scaling_multiply!(a2,b2,c2,d2,e2,f2)
      newa = @a * a2
      newb = @b * d2
      newc = @c * a2
      newd = @d * d2
      newe = @e * a2
      newf = @f * d2
      @a, @b, @c, @d, @e, @f = newa, newb, newc, newd, newe, newf
    end

    # Optimised method for when the first matrix in the calculation is
    # an X and Y scale
    #
    # Like this:
    #
    #   [ 5 0 0 ]   [ 1 2 0 ]
    #   [ 0 5 0 ] x [ 3 4 0 ]
    #   [ 0 0 1 ]   [ 5 6 1 ]
    #
    def xy_scaling_multiply_reversed!(a2,b2,c2,d2,e2,f2)
      newa = @a * a2
      newb = @a * b2
      newc = @d * c2
      newd = @d * d2
      newe = e2
      newf = f2
      @a, @b, @c, @d, @e, @f = newa, newb, newc, newd, newe, newf
    end

    # A general solution to multiplying two 3x3 matrixes. This is correct in all cases,
    # but slower due to excessive object allocations. It's not actually used in any
    # active code paths, but is here for reference. Use faster_multiply instead.
    #
    # Like this:
    #
    #   [ a b 0 ]   [ a b 0 ]
    #   [ c d 0 ] x [ c d 0 ]
    #   [ e f 1 ]   [ e f 1 ]
    #
    def regular_multiply!(a2,b2,c2,d2,e2,f2)
      newa = (@a * a2) + (@b * c2) + (0 * e2)
      newb = (@a * b2) + (@b * d2) + (0 * f2)
      newc = (@c * a2) + (@d * c2) + (0 * e2)
      newd = (@c * b2) + (@d * d2) + (0 * f2)
      newe = (@e * a2) + (@f * c2) + (1 * e2)
      newf = (@e * b2) + (@f * d2) + (1 * f2)
      @a, @b, @c, @d, @e, @f = newa, newb, newc, newd, newe, newf
    end

    # A general solution for multiplying two matrices when we know all values
    # in the final column are fixed. This is the fallback method for when none
    # of the optimised methods are applicable.
    #
    # Like this:
    #
    #   [ a b 0 ]   [ a b 0 ]
    #   [ c d 0 ] x [ c d 0 ]
    #   [ e f 1 ]   [ e f 1 ]
    #
    def faster_multiply!(a2,b2,c2, d2,e2,f2)
      newa = (@a * a2) + (@b * c2)
      newb = (@a * b2) + (@b * d2)
      newc = (@c * a2) + (@d * c2)
      newd = (@c * b2) + (@d * d2)
      newe = (@e * a2) + (@f * c2) + e2
      newf = (@e * b2) + (@f * d2) + f2
      @a, @b, @c, @d, @e, @f = newa, newb, newc, newd, newe, newf
    end
  end
end
