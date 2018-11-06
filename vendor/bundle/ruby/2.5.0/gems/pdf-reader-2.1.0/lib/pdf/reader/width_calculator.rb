# coding: utf-8

# PDF files may define fonts in a number of ways. Each approach means we must
# calculate glyph widths differently, so this set of classes conform to an
# interface that will perform the appropriate calculations.

require 'pdf/reader/width_calculator/built_in'
require 'pdf/reader/width_calculator/composite'
require 'pdf/reader/width_calculator/true_type'
require 'pdf/reader/width_calculator/type_zero'
require 'pdf/reader/width_calculator/type_one_or_three'
