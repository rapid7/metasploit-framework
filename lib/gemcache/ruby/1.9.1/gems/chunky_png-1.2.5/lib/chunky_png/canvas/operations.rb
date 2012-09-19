module ChunkyPNG
  class Canvas
    
    # The ChunkyPNG::Canvas::Operations module defines methods to perform operations
    # on a {ChunkyPNG::Canvas}. The module is included into the Canvas class so all
    # these methods are available on every canvas.
    #
    # Note that some of these operations modify the canvas, while some operations return 
    # a new canvas and leave the original intact.
    #
    # @see ChunkyPNG::Canvas
    module Operations
      
      # Converts the canvas to grascale.
      #
      # This method will modify the canvas. The obtain a new canvas and leave the 
      # current instance intact, use {#grayscale} instead.
      #
      # @return [ChunkyPNG::Canvas] Returns itself, converted to grayscale.
      # @see {#grayscale}
      # @see {ChunkyPNG::Color#to_grayscale}
      def grayscale!
        pixels.map! { |pixel| ChunkyPNG::Color.to_grayscale(pixel) }
        return self
      end

      # Converts the canvas to grascale, returning a new canvas.
      #
      # This method will not modify the canvas. To modift the current canvas,
      # use {#grayscale!} instead.
      #
      # @return [ChunkyPNG::Canvas] A copy of the canvas, converted to grasycale.
      # @see {#grayscale!}
      # @see {ChunkyPNG::Color#to_grayscale}
      def grayscale
        dup.grayscale!
      end
      
      # Composes another image onto this image using alpha blending. This will modify
      # the current canvas.
      #
      # If you simply want to replace pixels or when the other image does not have
      # transparency, it is faster to use {#replace!}.
      #
      # @param [ChunkyPNG::Canvas] other The foreground canvas to compose on the
      #     current canvas, using alpha compositing.
      # @param [Integer] offset_x The x-offset to apply the new foreground on.
      # @param [Integer] offset_y The y-offset to apply the new foreground on.
      # @return [ChunkyPNG::Canvas] Returns itself, but with the other canvas composed onto it.
      # @raise [ChunkyPNG::OutOfBounds] when the other canvas doesn't fit on this one,
      #     given the offset and size of the other canvas.
      # @see #replace!
      # @see #compose
      def compose!(other, offset_x = 0, offset_y = 0)
        check_size_constraints!(other, offset_x, offset_y)

        for y in 0...other.height do
          for x in 0...other.width do
            set_pixel(x + offset_x, y + offset_y, ChunkyPNG::Color.compose(other.get_pixel(x, y), get_pixel(x + offset_x, y + offset_y)))
          end
        end
        self
      end
      
      # Composes another image onto this image using alpha blending. This will return
      # a new canvas and leave the original intact.
      #
      # If you simply want to replace pixels or when the other image does not have
      # transparency, it is faster to use {#replace}.
      #
      # @param (see #compose!)
      # @return [ChunkyPNG::Canvas] Returns the new canvas, composed of the other 2.
      # @raise [ChunkyPNG::OutOfBounds] when the other canvas doesn't fit on this one,
      #     given the offset and size of the other canvas.
      #
      # @note API changed since 1.0 - This method now no longer is in place, but returns
      #     a new canvas and leaves the original intact. Use {#compose!} if you want to
      #     compose on the canvas in place.
      # @see #replace
      def compose(other, offset_x = 0, offset_y = 0)
        dup.compose!(other, offset_x, offset_y)
      end
      
      # Replaces pixels on this image by pixels from another pixels, on a given offset.
      # This method will modify the current canvas.
      #
      # This will completely replace the pixels of the background image. If you want to blend
      # them with semi-transparent pixels from the foreground image, see {#compose!}.
      #
      # @param [ChunkyPNG::Canvas] other The foreground canvas to get the pixels from.
      # @param [Integer] offset_x The x-offset to apply the new foreground on.
      # @param [Integer] offset_y The y-offset to apply the new foreground on.
      # @return [ChunkyPNG::Canvas] Returns itself, but with the other canvas placed onto it.
      # @raise [ChunkyPNG::OutOfBounds] when the other canvas doesn't fit on this one,
      #     given the offset and size of the other canvas.
      # @see #compose!
      # @see #replace
      def replace!(other, offset_x = 0, offset_y = 0)
        check_size_constraints!(other, offset_x, offset_y)

        for y in 0...other.height do
          for d in 0...other.width
            pixels[(y + offset_y) * width + offset_x + d] = other.pixels[y * other.width + d]
          end
        end
        self
      end

      # Replaces pixels on this image by pixels from another pixels, on a given offset.
      # This method will modify the current canvas.
      #
      # This will completely replace the pixels of the background image. If you want to blend
      # them with semi-transparent pixels from the foreground image, see {#compose!}.
      #
      # @param (see #replace!)
      # @return [ChunkyPNG::Canvas] Returns a new, combined canvas.
      # @raise [ChunkyPNG::OutOfBounds] when the other canvas doesn't fit on this one,
      #     given the offset and size of the other canvas.
      #
      # @note API changed since 1.0 - This method now no longer is in place, but returns
      #     a new canvas and leaves the original intact. Use {#replace!} if you want to
      #     replace pixels on the canvas in place.
      # @see #compose 
      def replace(other, offset_x = 0, offset_y = 0)
        dup.replace!(other, offset_x, offset_y)
      end

      # Crops an image, given the coordinates and size of the image that needs to be cut out.
      # This will leave the original image intact and return a new, cropped image with pixels
      # copied from the original image.
      #
      # @param [Integer] x The x-coordinate of the top left corner of the image to be cropped.
      # @param [Integer] y The y-coordinate of the top left corner of the image to be cropped.
      # @param [Integer] crop_width The width of the image to be cropped.
      # @param [Integer] crop_height The height of the image to be cropped.
      # @return [ChunkyPNG::Canvas] Returns the newly created cropped image.
      # @raise [ChunkyPNG::OutOfBounds] when the crop dimensions plus the given coordinates 
      #     are bigger then the original image.
      def crop(x, y, crop_width, crop_height)
        dup.crop!(x, y, crop_width, crop_height)
      end
      
      # Crops an image, given the coordinates and size of the image that needs to be cut out.
      #
      # This will change the size and content of the current canvas. Use {#crop} if you want to 
      # have a new canvas returned instead, leaving the current canvas intact.
      #
      # @param [Integer] x The x-coordinate of the top left corner of the image to be cropped.
      # @param [Integer] y The y-coordinate of the top left corner of the image to be cropped.
      # @param [Integer] crop_width The width of the image to be cropped.
      # @param [Integer] crop_height The height of the image to be cropped.
      # @return [ChunkyPNG::Canvas] Returns itself, but cropped. 
      # @raise [ChunkyPNG::OutOfBounds] when the crop dimensions plus the given coordinates 
      #     are bigger then the original image.      
      def crop!(x, y, crop_width, crop_height)
        
        raise ChunkyPNG::OutOfBounds, "Image width is too small!" if crop_width + x > width
        raise ChunkyPNG::OutOfBounds, "Image width is too small!" if crop_height + y > height
        
        new_pixels = []
        for cy in 0...crop_height do
          new_pixels += pixels.slice((cy + y) * width + x, crop_width)
        end
        replace_canvas!(crop_width, crop_height, new_pixels)
      end
      
      # Flips the image horizontally, leaving the original intact.
      #
      # This will flip the image on its horizontal axis, e.g. pixels on the top will now
      # be pixels on the bottom. Chaining this method twice will return the original canvas.
      # This method will leave the original object intact and return a new canvas.
      #
      # @return [ChunkyPNG::Canvas] The flipped image
      # @see #flip_horizontally!
      def flip_horizontally
        dup.flip_horizontally!
      end
      
      # Flips the image horizontally in place.
      #
      # This will flip the image on its horizontal axis, e.g. pixels on the top will now
      # be pixels on the bottom. Chaining this method twice will return the original canvas.
      # This method will leave the original object intact and return a new canvas.
      #
      # @return [ChunkyPNG::Canvas] Itself, but flipped
      # @see #flip_horizontally
      def flip_horizontally!
        for y in 0..((height - 1) >> 1) do
          other_y   = height - (y + 1)
          other_row = row(other_y)
          replace_row!(other_y, row(y))
          replace_row!(y, other_row)
        end
        return self
      end
      
      alias_method :flip!, :flip_horizontally!
      alias_method :flip,  :flip_horizontally
      
      # Flips the image vertically, leaving the original intact.
      #
      # This will flip the image on its vertical axis, e.g. pixels on the left will now
      # be pixels on the right. Chaining this method twice will return the original canvas.
      # This method will leave the original object intact and return a new canvas.
      #
      # @return [ChunkyPNG::Canvas] The flipped image
      # @see #flip_vertically!
      def flip_vertically
        dup.flip_vertically!
      end

      # Flips the image vertically in place.
      #
      # This will flip the image on its vertical axis, e.g. pixels on the left will now
      # be pixels on the right. Chaining this method twice will return the original canvas.
      # This method will leave the original object intact and return a new canvas.
      #
      # @return [ChunkyPNG::Canvas] Itself, but flipped
      # @see #flip_vertically
      def flip_vertically!
        for y in 0...height do
          replace_row!(y, row(y).reverse)
        end
        return self
      end
      
      alias_method :mirror!, :flip_vertically!
      alias_method :mirror,  :flip_vertically

      # Returns a new canvas instance that is rotated 90 degrees clockwise.
      #
      # This method will return a new canvas and leaves the original intact. 
      # See {#rotate_right!} for the in place version.
      #
      # @return [ChunkyPNG::Canvas] A clockwise-rotated copy.
      def rotate_right
        dup.rotate_right!
      end

      # Rotates the image 90 degrees clockwise in place.
      #
      # This method will change the current canvas. See {#rotate_right} for
      # a version that leaves th current canvas intact
      #
      # @return [ChunkyPNG::Canvas] Itself, but rotated clockwise.
      def rotate_right!
        rotated = self.class.new(height, width)
        new_pixels = []
        0.upto(width - 1) { |i| new_pixels += column(i).reverse }
        replace_canvas!(height, width, new_pixels)
      end
      
      alias_method :rotate_clockwise,  :rotate_right
      alias_method :rotate_clockwise!, :rotate_right!
      
      # Returns an image that is rotated 90 degrees counter-clockwise.
      #
      # This method will leave the original object intact and return a new canvas.
      # See {#rotate_left!} for the in place version.
      #
      # @return [ChunkyPNG::Canvas] A rotated copy of itself.
      def rotate_left
        dup.rotate_left!
      end
      
      # Rotates the image 90 degrees counter-clockwise in place.
      #
      # This method will change the original canvas. See {#rotate_left} for a
      # version that leaves the canvas intact and returns a new rotated canvas
      # instead.
      #
      # @return [ChunkyPNG::Canvas] Itself, but rotated.
      def rotate_left!
        new_pixels = []
        (width - 1).downto(0) { |i| new_pixels += column(i) }
        replace_canvas!(height, width, new_pixels)
      end
      
      alias_method :rotate_counter_clockwise,  :rotate_left
      alias_method :rotate_counter_clockwise!, :rotate_left!
      
      # Rotates the image 180 degrees.
      # This method will leave the original object intact and return a new canvas.
      #
      # @return [ChunkyPNG::Canvas] The rotated image.
      # @see #rotate_180!
      def rotate_180
        dup.rotate_180!
      end
      
      # Rotates the image 180 degrees in place.
      #
      # @return [ChunkyPNG::Canvas] Itself, but rotated 180 degrees.
      # @see #rotate_180
      def rotate_180!
        pixels.reverse!
        return self
      end
      
      protected
      
      # Checks whether another image has the correct dimension to be used for an operation
      # on the current image, given an offset coordinate to work with.
      # @param [ChunkyPNG::Canvas] other The other canvas
      # @param [Integer] offset_x The x offset on which the other image will be applied.
      # @param [Integer] offset_y The y offset on which the other image will be applied.
      # @raise [ChunkyPNG::OutOfBounds] when the other image doesn't fit.
      def check_size_constraints!(other, offset_x, offset_y)
        raise ChunkyPNG::OutOfBounds, "Background image width is too small!"  if width  < other.width  + offset_x
        raise ChunkyPNG::OutOfBounds, "Background image height is too small!" if height < other.height + offset_y
      end
    end
  end
end
