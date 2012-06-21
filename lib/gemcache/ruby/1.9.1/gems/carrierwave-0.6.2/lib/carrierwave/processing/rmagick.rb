# encoding: utf-8

unless defined? Magick
  begin
    require 'rmagick'
  rescue LoadError
    require 'RMagick'
  rescue LoadError
    puts "WARNING: Failed to require rmagick, image processing may fail!"
  end
end

module CarrierWave

  ##
  # This module simplifies manipulation with RMagick by providing a set
  # of convenient helper methods. If you want to use them, you'll need to
  # require this file:
  #
  #     require 'carrierwave/processing/rmagick'
  #
  # And then include it in your uploader:
  #
  #     class MyUploader < CarrierWave::Uploader::Base
  #       include CarrierWave::RMagick
  #     end
  #
  # You can now use the provided helpers:
  #
  #     class MyUploader < CarrierWave::Uploader::Base
  #       include CarrierWave::RMagick
  #
  #       process :resize_to_fit => [200, 200]
  #     end
  #
  # Or create your own helpers with the powerful manipulate! method. Check
  # out the RMagick docs at http://www.imagemagick.org/RMagick/doc/ for more
  # info
  #
  #     class MyUploader < CarrierWave::Uploader::Base
  #       include CarrierWave::RMagick
  #
  #       process :do_stuff => 10.0
  #
  #       def do_stuff(blur_factor)
  #         manipulate! do |img|
  #           img = img.sepiatone
  #           img = img.auto_orient
  #           img = img.radial_blur(blur_factor)
  #         end
  #       end
  #     end
  #
  # === Note
  #
  # You should be aware how RMagick handles memory. manipulate! takes care
  # of freeing up memory for you, but for optimum memory usage you should
  # use destructive operations as much as possible:
  #
  # DON'T DO THIS:
  #     img = img.resize_to_fit
  #
  # DO THIS INSTEAD:
  #     img.resize_to_fit!
  #
  # Read this for more information why:
  #
  # http://rubyforge.org/forum/forum.php?thread_id=1374&forum_id=1618
  #
  module RMagick
    extend ActiveSupport::Concern

    module ClassMethods
      def convert(format)
        process :convert => format
      end

      def resize_to_limit(width, height)
        process :resize_to_limit => [width, height]
      end

      def resize_to_fit(width, height)
        process :resize_to_fit => [width, height]
      end

      def resize_to_fill(width, height, gravity=::Magick::CenterGravity)
        process :resize_to_fill => [width, height, gravity]
      end

      def resize_and_pad(width, height, background=:transparent, gravity=::Magick::CenterGravity)
        process :resize_and_pad => [width, height, background, gravity]
      end
    end

    ##
    # Changes the image encoding format to the given format
    #
    # See even http://www.imagemagick.org/RMagick/doc/magick.html#formats
    #
    # === Parameters
    #
    # [format (#to_s)] an abreviation of the format
    #
    # === Yields
    #
    # [Magick::Image] additional manipulations to perform
    #
    # === Examples
    #
    #     image.convert(:png)
    #
    def convert(format)
      manipulate!(:format => format)
    end

    ##
    # Resize the image to fit within the specified dimensions while retaining
    # the original aspect ratio. Will only resize the image if it is larger than the
    # specified dimensions. The resulting image may be shorter or narrower than specified
    # in the smaller dimension but will not be larger than the specified values.
    #
    # === Parameters
    #
    # [width (Integer)] the width to scale the image to
    # [height (Integer)] the height to scale the image to
    #
    # === Yields
    #
    # [Magick::Image] additional manipulations to perform
    #
    def resize_to_limit(width, height)
      manipulate! do |img|
        geometry = Magick::Geometry.new(width, height, 0, 0, Magick::GreaterGeometry)
        new_img = img.change_geometry(geometry) do |new_width, new_height|
          img.resize(new_width, new_height)
        end
        destroy_image(img)
        new_img = yield(new_img) if block_given?
        new_img
      end
    end

    ##
    # From the RMagick documentation: "Resize the image to fit within the
    # specified dimensions while retaining the original aspect ratio. The
    # image may be shorter or narrower than specified in the smaller dimension
    # but will not be larger than the specified values."
    #
    # See even http://www.imagemagick.org/RMagick/doc/image3.html#resize_to_fit
    #
    # === Parameters
    #
    # [width (Integer)] the width to scale the image to
    # [height (Integer)] the height to scale the image to
    #
    # === Yields
    #
    # [Magick::Image] additional manipulations to perform
    #
    def resize_to_fit(width, height)
      manipulate! do |img|
        img.resize_to_fit!(width, height)
        img = yield(img) if block_given?
        img
      end
    end

    ##
    # From the RMagick documentation: "Resize the image to fit within the
    # specified dimensions while retaining the aspect ratio of the original
    # image. If necessary, crop the image in the larger dimension."
    #
    # See even http://www.imagemagick.org/RMagick/doc/image3.html#resize_to_fill
    #
    # === Parameters
    #
    # [width (Integer)] the width to scale the image to
    # [height (Integer)] the height to scale the image to
    #
    # === Yields
    #
    # [Magick::Image] additional manipulations to perform
    #
    def resize_to_fill(width, height, gravity=::Magick::CenterGravity)
      manipulate! do |img|
        img.crop_resized!(width, height, gravity)
        img = yield(img) if block_given?
        img
      end
    end

    ##
    # Resize the image to fit within the specified dimensions while retaining
    # the original aspect ratio. If necessary, will pad the remaining area
    # with the given color, which defaults to transparent (for gif and png,
    # white for jpeg).
    #
    # === Parameters
    #
    # [width (Integer)] the width to scale the image to
    # [height (Integer)] the height to scale the image to
    # [background (String, :transparent)] the color of the background as a hexcode, like "#ff45de"
    # [gravity (Magick::GravityType)] how to position the image
    #
    # === Yields
    #
    # [Magick::Image] additional manipulations to perform
    #
    def resize_and_pad(width, height, background=:transparent, gravity=::Magick::CenterGravity)
      manipulate! do |img|
        img.resize_to_fit!(width, height)
        new_img = ::Magick::Image.new(width, height)
        if background == :transparent
          filled = new_img.matte_floodfill(1, 1)
        else
          filled = new_img.color_floodfill(1, 1, ::Magick::Pixel.from_color(background))
        end
        destroy_image(new_img)
        filled.composite!(img, gravity, ::Magick::OverCompositeOp)
        destroy_image(img)
        filled = yield(filled) if block_given?
        filled
      end
    end

    ##
    # Manipulate the image with RMagick. This method will load up an image
    # and then pass each of its frames to the supplied block. It will then
    # save the image to disk.
    #
    # === Gotcha
    #
    # This method assumes that the object responds to +current_path+.
    # Any class that this module is mixed into must have a +current_path+ method.
    # CarrierWave::Uploader does, so you won't need to worry about this in
    # most cases.
    #
    # === Yields
    #
    # [Magick::Image] manipulations to perform
    #
    # === Raises
    #
    # [CarrierWave::ProcessingError] if manipulation failed.
    #
    def manipulate!(options={}, &block)
      cache_stored_file! if !cached?
      image = ::Magick::Image.read(current_path)

      frames = if image.size > 1
        list = ::Magick::ImageList.new
        image.each_with_index do |frame, index|
          processed_frame = if block_given?
            yield *[frame, index].take(block.arity)
          else
            frame
          end
          list << processed_frame if processed_frame
        end
        block_given? ? list : list.append(true)
      else
        frame = image.first
        frame = yield( *[frame, 0].take(block.arity) ) if block_given?
        frame
      end

      if options[:format]
        frames.write("#{options[:format]}:#{current_path}")
      else
        frames.write(current_path)
      end
      destroy_image(frames)
    rescue ::Magick::ImageMagickError => e
      raise CarrierWave::ProcessingError, I18n.translate(:"errors.messages.rmagick_processing_error", :e => e)
    end

  private

    def destroy_image(image)
      image.destroy! if image.respond_to?(:destroy!)
    end

  end # RMagick
end # CarrierWave
