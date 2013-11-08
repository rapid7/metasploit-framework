# Synchronizes {#metasploit_instance metasploit instance's}
# {Msf::Module#references} to
# {#module_instance} `Metasploit::Model::Module::Instance#module_references`.
class Metasploit::Framework::Module::Instance::Synchronization::ModuleReferences < Metasploit::Framework::Module::Instance::Synchronization::Base
  #
  # CONSTANTS
  #

  ALLOW_BY_ATTRIBUTE = {
      module_references: true
  }

  #
  # Synchronization
  #

  synchronize do
    destroy_removed
    build_added
  end

  #
  # Methods
  #

  def added_authority_abbreviations
    @added_authority_abbreviations ||= added_attributes_set.each_with_object([]) { |attributes, added_authority_abbreviations|
      authority_attributes = attributes[:authority]

      if authority_attributes
        added_authority_abbreviations << authority_attributes[:abbreviation]
      end
    }
  end

  def authority_by_abbreviation
    # get pre-existing authorities in bulk
    @authority_by_abbreviation ||= Mdm::Authority.where(
        abbreviation: added_authority_abbreviations
    ).each_with_object({}) { |authority, authority_by_abbreviation|
      authority_by_abbreviation[authority.abbreviation] = authority
    }
  end

  def build_added
    added_attributes_set.each do |attributes|
      reference = reference_by_attributes[attributes]

      unless reference
        authority_attributes = attributes[:authority]

        if authority_attributes
          abbreviation = authority_attributes[:abbreviation]

          authority = authority_by_abbreviation[abbreviation]

          unless authority
            authority = Mdm::Authority.new(abbreviation: abbreviation)
            authority_by_abbreviation[abbreviation] = authority
          end

          designation = attributes[:designation]

          reference = authority.references.build(
              designation: designation
          )
        else
          url = attributes[:url]

          reference = Mdm::Reference.new(
              url: url
          )
        end

        reference_by_attributes[attributes] = reference
      end

      destination.module_references.build(
          reference: reference
      )
    end
  end

  def destination_attributes_set
    @destination_attributes_set = scope.each_with_object(Set.new) { |module_reference, set|
      attributes = {}

      reference = module_reference.reference
      authority = reference.authority

      if authority
        attributes[:authority] = {
            abbreviation: authority.abbreviation
        }
        attributes[:designation] = reference.designation
        # don't use the reference.url since the metasploit-framework API doesn't support URLs for designations
      else
        # without an authority, only have the URL
        attributes[:url] = reference.url
      end

      attributes
    }
  end

  def destroy_removed
    scope.where(destroy_removed_condition).destroy_all
  end

  def destroy_removed_condition
    removed_attributes_set_conditions.inject { |condition, attributes_condition|
      condition.or(attributes_condition)
    }
  end

  def reference_condition
    reference_conditions.inject { |condition, reference_condition|
      condition.or(reference_condition)
    }
  end

  def reference_by_attributes
    # get pre-existing references in bulk
    @reference_by_attributes ||= Mdm::Reference.includes(:authority).where(
        reference_condition
    ).each_with_object({}) { |reference, reference_by_attributes|
      authority = reference.authority

      if authority
        attributes = {
            authority: {
                abbreviation: authority.abbreviation
            },
            designation: reference.designation
        }
      else
        attributes = {
            url: reference.url
        }
      end

      reference_by_attributes[attributes] = reference
    }
  end

  def reference_conditions
    added_attributes_set.each_with_object([]) { |attributes, reference_conditions|
      authority_attributes = attributes[:authority]

      # if has authority
      if authority_attributes
        abbreviation = authority_attributes[:abbreviation]
        authority = authority_by_abbreviation[abbreviation]

        if authority
          authority_id = authority.id

          # if authority already exists
          if authority_id
            authority_id_condition = Mdm::Reference.arel_table[:authority_id].eq(authority_id)

            designation = attributes[:designation]
            designation_condition = Mdm::Reference.arel_table[:designation].eq(designation)

            reference_condition = authority_id_condition.and(designation_condition)
            reference_conditions << reference_condition
          end
        end
      else
        url = attributes[:url]
        reference_condition = Mdm::Reference.arel_table[:url].eq(url)
        reference_conditions << reference_condition
      end
    }
  end

  def removed_attributes_set_conditions
    removed_attributes_set.collect { |attributes|
      url = attributes[:url]

      if url
        Mdm::Reference.arel_table[:url].eq(url)
      else
        designation = attributes[:designation]
        designation_condition = Mdm::Reference.arel_table[:designation].eq(designation)

        authority_abbreviation = attributes[:authority][:abbreviation]
        authority_abbreviation_condition = Mdm::Authority.arel_table[:abbreviation].eq(authority_abbreviation)

        designation_condition.and(authority_abbreviation_condition)
      end
    }
  end

  def scope
    destination.module_references.includes(reference: :authority)
  end

  def source_attributes_set
    @source_attributes_set = source_references.each_with_object(Set.new) { |msf_module_reference, set|
      case msf_module_reference
        # must be before Msf::Module::Reference so subclass matches before superclass
        when Msf::Module::SiteReference
          msf_module_site_reference = msf_module_reference

          if msf_module_site_reference.ctx_id == 'URL'
            attributes = {
                url: msf_module_site_reference.ctx_val
            }
          else
            attributes = {
                authority: {
                    abbreviation: msf_module_site_reference.ctx_id
                },
                designation: msf_module_site_reference.ctx_val
            }
          end
        when Msf::Module::Reference
          raise NotImplementedError
        else
          raise ArgumentError
      end

      set.add attributes
    }
  end

  def source_references
    begin
      source.references
    rescue NoMethodError => error
      log_module_instance_error(destination, error)

      []
    end
  end
end