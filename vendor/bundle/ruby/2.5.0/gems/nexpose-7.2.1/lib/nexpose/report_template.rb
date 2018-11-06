module Nexpose

  class Connection
    include XMLUtils

    # Provide a list of all report templates the user can access on the
    # Security Console.
    #
    # @return [Array[ReportTemplateSummary]] List of current report templates.
    #
    def list_report_templates
      r = execute(make_xml('ReportTemplateListingRequest', {}))
      templates = []
      if r.success
        r.res.elements.each('//ReportTemplateSummary') do |template|
          templates << ReportTemplateSummary.parse(template)
        end
      end
      templates
    end

    alias report_templates list_report_templates

    # Deletes an existing, custom report template.
    # Cannot delete built-in templates.
    #
    # @param [String] template_id Unique identifier of the report template to remove.
    #
    def delete_report_template(template_id)
      AJAX.delete(self, "/data/report/templates/#{URI.escape(template_id)}")
    end
  end

  # Data object for report template summary information.
  # Not meant for use in creating new templates.
  #
  class ReportTemplateSummary

    # The ID of the report template.
    attr_reader :id
    # The name of the report template.
    attr_reader :name
    # One of: data|document. With a data template, you can export
    # comma-separated value (CSV) files with vulnerability-based data.
    # With a document template, you can create PDF, RTF, HTML, or XML reports
    # with asset-based information.
    attr_reader :type
    # The visibility (scope) of the report template. One of: global|silo
    attr_reader :scope
    # Whether the report template is built-in, and therefore cannot be modified.
    attr_reader :built_in
    # Description of the report template.
    attr_reader :description

    def initialize(id, name, type, scope, built_in, description)
      @id          = id
      @name        = name
      @type        = type
      @scope       = scope
      @built_in    = built_in
      @description = description
    end

    def delete(connection)
      connection.delete_report_template(@id)
    end

    def self.parse(xml)
      description = nil
      xml.elements.each('description') { |desc| description = desc.text }
      ReportTemplateSummary.new(xml.attributes['id'],
                                xml.attributes['name'],
                                xml.attributes['type'],
                                xml.attributes['scope'],
                                xml.attributes['builtin'] == '1',
                                description)
    end
  end

  # Definition object for a report template.
  #
  class ReportTemplate

    # The ID of the report template.
    attr_accessor :id
    # The name of the report template.
    attr_accessor :name
    # With a data template, you can export comma-separated value (CSV) files
    # with vulnerability-based data. With a document template, you can create
    # PDF, RTF, HTML, or XML reports with asset-based information. When you
    # retrieve a report template, the type will always be visible even though
    # type is implied. When ReportTemplate is sent as a request, and the type
    # attribute is not provided, the type attribute defaults to document,
    # allowing for backward compatibility with existing API clients.
    attr_accessor :type
    # The visibility (scope) of the report template.
    # One of: global|silo
    attr_accessor :scope
    # The report template is built-in, and cannot be modified.
    attr_accessor :built_in
    # Description of this report template.
    attr_accessor :description

    # Array of report sections.
    attr_accessor :sections
    # Map of report properties.
    attr_accessor :properties
    # Array of report attributes, in the order they will be present in a report.
    attr_accessor :attributes
    # Display asset names with IPs.
    attr_accessor :show_asset_names
    alias show_device_names show_asset_names
    alias show_device_names= show_asset_names=

    def initialize(name, type = 'document', id = -1, scope = 'silo', built_in = false)
      @name             = name
      @type             = type
      @id               = id
      @scope            = scope
      @built_in         = built_in
      @sections         = []
      @properties       = {}
      @attributes       = []
      @show_asset_names = false
    end

    # Save the configuration for a report template.
    def save(connection)
      xml = %(<ReportTemplateSaveRequest session-id='#{connection.session_id}' scope='#{@scope}'>)
      xml << to_xml
      xml << '</ReportTemplateSaveRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['template-id']
      end
    end

    # Retrieve the configuration for a report template.
    def self.load(connection, template_id)
      xml = %(<ReportTemplateConfigRequest session-id='#{connection.session_id}' template-id='#{template_id}'/>)
      ReportTemplate.parse(connection.execute(xml))
    end

    def delete(connection)
      connection.delete_report_template(@id)
    end

    include Sanitize

    def to_xml
      xml = %(<ReportTemplate id='#{@id}' name='#{@name}' type='#{@type}')
      xml << %( scope='#{@scope}') if @scope
      xml << %( builtin='#{@built_in}') if @built_in
      xml << '>'
      xml << %(<description>#{@description}</description>) if @description

      unless @attributes.empty?
        xml << '<ReportAttributes>'
        @attributes.each do |attr|
          xml << %(<ReportAttribute name='#{attr}'/>)
        end
        xml << '</ReportAttributes>'
      end

      unless @sections.empty?
        xml << '<ReportSections>'
        properties.each_pair do |name, value|
          xml << %(<property name='#{name}'>#{replace_entities(value)}</property>)
        end
        @sections.each { |section| xml << section.to_xml }
        xml << '</ReportSections>'
      end

      xml << %(<Settings><showDeviceNames enabled='#{@show_asset_names ? 1 : 0}' /></Settings>)
      xml << '</ReportTemplate>'
    end

    def self.parse(xml)
      xml.res.elements.each('//ReportTemplate') do |tmp|
        template = ReportTemplate.new(tmp.attributes['name'],
                                      tmp.attributes['type'],
                                      tmp.attributes['id'],
                                      tmp.attributes['scope'] || 'silo',
                                      tmp.attributes['builtin'])
        tmp.elements.each('//description') do |desc|
          template.description = desc.text
        end

        tmp.elements.each('//ReportAttributes/ReportAttribute') do |attr|
          template.attributes << attr.attributes['name']
        end

        tmp.elements.each('//ReportSections/property') do |property|
          template.properties[property.attributes['name']] = property.text
        end

        tmp.elements.each('//ReportSection') do |section|
          template.sections << Section.parse(section)
        end

        tmp.elements.each('//showDeviceNames') do |show|
          template.show_asset_names = show.attributes['enabled'] == '1'
        end

        return template
      end
      nil
    end
  end

  # Section specific content to include in a report template.
  #
  class Section

    # Name of the report section.
    attr_accessor :name
    # Map of properties specific to the report section.
    attr_accessor :properties

    def initialize(name)
      @name       = name
      @properties = {}
    end

    include Sanitize

    def to_xml
      xml = %(<ReportSection name='#{@name}'>)
      properties.each_pair do |name, value|
        xml << %(<property name='#{name}'>#{replace_entities(value)}</property>)
      end
      xml << '</ReportSection>'
    end

    def self.parse(xml)
      name = xml.attributes['name']
      xml.elements.each("//ReportSection[@name='#{name}']") do |elem|
        section = Section.new(name)
        elem.elements.each("//ReportSection[@name='#{name}']/property") do |property|
          section.properties[property.attributes['name']] = property.text
        end
        return section
      end
      nil
    end
  end
end
