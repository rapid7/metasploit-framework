# frozen_string_literal: true
include T('default/layout/html')

def init
  super

  @topfile = options.readme
  if options.files
    if @topfile
      @toptitle = @topfile.attributes[:title] || "Documentation Overview"
    end
    @page_title = @file == options.readme ? options.title : @file.title

    index = options.files.index(@file)
    if index
      @prevfile = index > 0 ? (options.files[index - 1] || options.readme) : nil
      @nextfile = options.files[index + 1]
    end
  end
end

def diskfile
  options.including_object = @object
  super
end
