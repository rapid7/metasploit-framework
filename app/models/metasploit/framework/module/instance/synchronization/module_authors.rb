# Synchronizes {#metasploit_instance metasploit instance's} {Msf::Module#authors authors} to
# {#module_instance} `Metasploit::Model::Module::Instance#module_authors`.
class Metasploit::Framework::Module::Instance::Synchronization::ModuleAuthors < Metasploit::Framework::Module::Instance::Synchronization::Base
  #
  # CONSTANTS
  #

  # All module support authors, so no restrictions
  ALLOW_BY_ATTRIBUTE = {}

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

  def added_author_names
    @added_author_names ||= added_attributes_set.collect { |added_attributes|
      added_attributes[:author][:name]
    }
  end

  def added_email_address_fulls
    @added_email_address_fulls ||= added_attributes_set.each_with_object([]) { |added_attributes, added_email_address_fulls|
      email_address_attributes = added_attributes[:email_address]

      if email_address_attributes
        added_email_address_fulls << email_address_attributes[:full]
      end
    }
  end

  def author_by_name
    # get pre-existing authors in bulk
    @author_by_name ||= Mdm::Author.where(
        name: added_author_names
    ).each_with_object({}) { |author, author_by_name|
      author_by_name[author.name] = author
    }
  end

  def build_added
    added_attributes_set.each do |added_attributes|
      author_name = added_attributes[:author][:name]
      author = author_by_name[author_name]

      unless author
        author = Mdm::Author.new(name: author_name)
        author_by_name[author_name] = author
      end

      email_address = nil
      email_address_attributes = added_attributes[:email_address]

      if email_address_attributes
        email_address_full = email_address_attributes[:full]
        email_address = email_address_by_full[email_address_full]

        unless email_address
          email_address = Mdm::EmailAddress.new(full: email_address_full)
          email_address_by_full[email_address_full] = email_address
        end
      end

      destination.module_authors.build(
          author: author,
          email_address: email_address
      )
    end
  end

  def destination_attributes_set
    @destination_attributes_set ||= scope.each_with_object(Set.new) { |module_author|
      attributes = {
          author: {
              name: module_author.author.name
          }
      }

      email_address = module_author.email_address

      if email_address
        attributes[:email_address] = {
            full: email_address.full
        }
      end

      attributes
    }
  end

  def destroy_removed
    removed_set_conditions = removed_attributes_set.inject(nil) { |set_conditions, removed_attributes|
      attributes_conditions = Mdm::Author.arel_table[:name].eq(removed_attributes[:author][:name])

      email_address_attributes = removed_attributes[:email_address]

      if email_address_attributes
        attributes_conditions = attributes_conditions.and(
            Mdm::EmailAddress.arel_table[:full].eq(email_address_attributes[:full])
        )
      else
        attributes_conditions = attributes_conditions.and(
            Mdm::Module::Author.arel_table[:email_address_id].eq(nil)
        )
      end

      if set_conditions
        set_conditions.or(
            attributes_conditions
        )
      else
        attributes_conditions
      end
    }

    scope.where(removed_set_conditions).destroy_all
  end

  def email_address_by_full
    # get pre-existing email_addresses in bulk
    @email_address_by_full ||= Mdm::EmailAddress.where(
        full: added_email_address_fulls
    ).each_with_object({}) { |email_address, email_address_by_full|
      email_address_by_full[email_address.full] = email_address
    }
  end

  def scope
    destination.module_authors.includes(:author, :email_address)
  end

  def source_authors
    begin
      source.authors
    rescue NoMethodError => error
      log_module_instance_error(destination, error)

      []
    end
  end

  def source_attributes_set
    @source_attributes_set ||= source_authors.each_with_object(Set.new) { |msf_module_author, set|
      attributes = {
          author: {
              name: msf_module_author.name
          }
      }

      email = msf_module_author.email

      if email.present?
        attributes[:email_address] = {
            full: email
        }
      end

      set.add attributes
    }
  end
end