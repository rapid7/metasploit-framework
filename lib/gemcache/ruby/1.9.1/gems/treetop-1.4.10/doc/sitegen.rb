class Layout < Erector::Widget

  class << self
    def inherited(page_class)
      puts page_class
      (@@page_classes ||= []) << page_class
    end

    def generate_site
      FileUtils.mkdir_p(site_dir)
      @@page_classes.each do |page_class|
        page_class.generate_html unless page_class.abstract?
        puts page_class
      end
    end

    def generate_html
      File.open(absolute_path, 'w') do |file|
        file.write(new.to_html)
      end
    end

    def absolute_path
      absolutize(relative_path)
    end

    def relative_path
      "#{name.gsub('::', '_').underscore}.html"
    end

    def absolutize(relative_path)
      File.join(site_dir, relative_path)
    end

    def abstract
      @abstract = true
    end

    def abstract?
      @abstract
    end

    def site_dir
      File.join(File.dirname(__FILE__), "site")
    end
  end

  def bluecloth(relative_path)
    File.open(File.join(File.dirname(__FILE__), relative_path)) do |file|
      rawtext BlueCloth.new(file.read).to_html
    end
  end

  def absolutize(relative_path)
    self.class.absolutize(relative_path)
  end

  def link_to(link_text, page_class, section_class=nil)
    if instance_of?(page_class) || section_class && is_a?(section_class)
      text link_text
    else
      a link_text, :href => page_class.relative_path
    end
  end
end
