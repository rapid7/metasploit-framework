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

  def added_author_name_set
    @added_author_name_set ||= added_attributes_set.each_with_object(Set.new) { |added_attributes, set|
      set.add added_attributes[:author][:name]
    }
  end

  def added_email_address_full_set
    @added_email_address_full_set ||= added_attributes_set.each_with_object(Set.new) { |added_attributes, set|
      email_address_attributes = added_attributes[:email_address]

      if email_address_attributes
        set.add email_address_attributes[:full]
      end
    }
  end

  def author_by_name
    unless instance_variable_defined? :@author_by_name
      author_by_name = Hash.new { |hash, name|
        hash[name] = Mdm::Author.new(name: name)
      }

      # avoid querying database with `IN (NULL)`
      if added_author_name_set.empty?
        @author_by_name = author_by_name
      else
        # get pre-existing authors in bulk
        @author_by_name = Mdm::Author.where(
            # AREL cannot visit Set
            name: added_author_name_set.to_a
        ).each_with_object(author_by_name) { |author, author_by_name|
          author_by_name[author.name] = author
        }
      end
    end

    @author_by_name
  end

  def build_added
    added_attributes_set.each do |added_attributes|
      author_name = added_attributes[:author][:name]
      author = author_by_name[author_name]

      email_address = nil
      email_address_attributes = added_attributes[:email_address]

      if email_address_attributes
        email_address_full = email_address_attributes[:full]
        email_address = email_address_by_full[email_address_full]
      end

      destination.module_authors.build(
          author: author,
          email_address: email_address
      )
    end
  end

  def destination_attributes_set
    unless instance_variable_defined? :@destination_attributes_set
      if destination.new_record?
        @destination_attributes_set = Set.new
      else
        @destination_attributes_set = scope.each_with_object(Set.new) { |module_author, set|
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

          set.add attributes
        }
      end
    end

    @destination_attributes_set
  end

  def destroy_removed
    unless destination.new_record? || removed_attributes_set.empty?
      attributes_conditions_list = removed_attributes_set.collect { |removed_attributes|
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

        attributes_conditions
      }

      removed_set_conditions = attributes_conditions_list.inject { |set_conditions, attributes_conditions|
        set_conditions.or(attributes_conditions)
      }

      scope.where(removed_set_conditions).destroy_all
    end
  end

  def email_address_by_full
    unless instance_variable_defined? :@email_address_by_full
      email_address_by_full = Hash.new { |hash, full|
        hash[full] = Mdm::EmailAddress.new(full: full)
      }

      if added_email_address_full_set.empty?
        @email_address_by_full = email_address_by_full
      else
        @email_address_by_full = Mdm::EmailAddress.where(
            # AREL cannot visit Set
            full: added_email_address_full_set.to_a
        ).each_with_object(email_address_by_full) { |email_address, email_address_by_full|
          email_address_by_full[email_address.full] = email_address
        }
      end
    end

    @email_address_by_full
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