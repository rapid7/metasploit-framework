# encoding: utf-8

module CarrierWave
  module Test

    ##
    # These are some matchers that can be used in RSpec specs, to simplify the testing
    # of uploaders.
    #
    module Matchers

      class BeIdenticalTo # :nodoc:
        def initialize(expected)
          @expected = expected
        end

        def matches?(actual)
          @actual = actual
          FileUtils.identical?(@actual, @expected)
        end

        def failure_message
          "expected #{@actual.inspect} to be identical to #{@expected.inspect}"
        end

        def negative_failure_message
          "expected #{@actual.inspect} to not be identical to #{@expected.inspect}"
        end

        def description
          "be identical to #{@expected.inspect}"
        end
      end

      def be_identical_to(expected)
        BeIdenticalTo.new(expected)
      end

      class HavePermissions # :nodoc:
        def initialize(expected)
          @expected = expected
        end

        def matches?(actual)
          @actual = actual
          # Satisfy expectation here. Return false or raise an error if it's not met.
          (File.stat(@actual.path).mode & 0777) == @expected
        end

        def failure_message
          "expected #{@actual.current_path.inspect} to have permissions #{@expected.to_s(8)}, but they were #{(File.stat(@actual.path).mode & 0777).to_s(8)}"
        end

        def negative_failure_message
          "expected #{@actual.current_path.inspect} not to have permissions #{@expected.to_s(8)}, but it did"
        end

        def description
          "have permissions #{@expected.to_s(8)}"
        end
      end

      def have_permissions(expected)
        HavePermissions.new(expected)
      end

      class BeNoLargerThan # :nodoc:
        def initialize(width, height)
          @width, @height = width, height
        end

        def matches?(actual)
          @actual = actual
          # Satisfy expectation here. Return false or raise an error if it's not met.
          image = ImageLoader.load_image(@actual.current_path)
          @actual_width = image.width
          @actual_height = image.height
          @actual_width <= @width && @actual_height <= @height
        end

        def failure_message
          "expected #{@actual.current_path.inspect} to be no larger than #{@width} by #{@height}, but it was #{@actual_width} by #{@actual_height}."
        end

        def negative_failure_message
          "expected #{@actual.current_path.inspect} to be larger than #{@width} by #{@height}, but it wasn't."
        end

        def description
          "be no larger than #{@width} by #{@height}"
        end
      end

      def be_no_larger_than(width, height)
        BeNoLargerThan.new(width, height)
      end

      class HaveDimensions # :nodoc:
        def initialize(width, height)
          @width, @height = width, height
        end

        def matches?(actual)
          @actual = actual
          # Satisfy expectation here. Return false or raise an error if it's not met.
          image = ImageLoader.load_image(@actual.current_path)
          @actual_width = image.width
          @actual_height = image.height
          @actual_width == @width && @actual_height == @height
        end

        def failure_message
          "expected #{@actual.current_path.inspect} to have an exact size of #{@width} by #{@height}, but it was #{@actual_width} by #{@actual_height}."
        end

        def negative_failure_message
          "expected #{@actual.current_path.inspect} not to have an exact size of #{@width} by #{@height}, but it did."
        end

        def description
          "have an exact size of #{@width} by #{@height}"
        end
      end

      def have_dimensions(width, height)
        HaveDimensions.new(width, height)
      end

      class BeNoWiderThan # :nodoc:
        def initialize(width)
          @width = width
        end

        def matches?(actual)
          @actual = actual
          # Satisfy expectation here. Return false or raise an error if it's not met.
          image = ImageLoader.load_image(@actual.current_path)
          @actual_width = image.width
          @actual_width <= @width
        end

        def failure_message
          "expected #{@actual.current_path.inspect} to be no wider than #{@width}, but it was #{@actual_width}."
        end

        def negative_failure_message
          "expected #{@actual.current_path.inspect} not to be wider than #{@width}, but it is."
        end

        def description
          "have a width less than or equal to #{@width}"
        end
      end

      def be_no_wider_than(width)
        BeNoWiderThan.new(width)
      end

      class BeNoTallerThan # :nodoc:
        def initialize(height)
          @height = height
        end

        def matches?(actual)
          @actual = actual
          # Satisfy expectation here. Return false or raise an error if it's not met.
          image = ImageLoader.load_image(@actual.current_path)
          @actual_height = image.height
          @actual_height <= @height
        end

        def failure_message
          "expected #{@actual.current_path.inspect} to be no taller than #{@height}, but it was #{@actual_height}."
        end

        def negative_failure_message
          "expected #{@actual.current_path.inspect} not to be taller than #{@height}, but it is."
        end

        def description
          "have a height less than or equal to #{@height}"
        end
      end

      def be_no_taller_than(height)
        BeNoTallerThan.new(height)
      end

      class ImageLoader # :nodoc:
        def self.load_image(filename)
          if defined? ::MiniMagick
            MiniMagickWrapper.new(filename)
          else
            unless defined? ::Magick
              begin
                require 'rmagick'
              rescue LoadError
                require 'RMagick'
              rescue LoadError
                puts "WARNING: Failed to require rmagick, image processing may fail!"
              end
            end
            MagickWrapper.new(filename)
          end
        end
      end

      class MagickWrapper # :nodoc:
        attr_reader :image
        def width
          image.columns
        end

        def height
          image.rows
        end

        def initialize(filename)
          @image = ::Magick::Image.read(filename).first
        end
      end

      class MiniMagickWrapper # :nodoc:
        attr_reader :image
        def width
          image[:width]
        end

        def height
          image[:height]
        end

        def initialize(filename)
          @image = ::MiniMagick::Image.open(filename)
        end
      end

    end # Matchers
  end # Test
end # CarrierWave

