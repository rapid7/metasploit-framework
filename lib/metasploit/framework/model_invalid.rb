# Equivalent of `ActiveRecord::RecordInvalid` for metasploit-framework
# models under {Metasploit::Framework}.  It is needed because ActiveModel
# has no equivalent for `ActiveRecord::RecordInvalid`.  It only has
# `ActiveModel::StrictValidationFailed`, which is meant to be raised when
# `validates!` is called, which isn't the case in Metasploit::Framework's
# usage.
class Metasploit::Framework::ModelInvalid < Metasploit::Framework::Error
	#
	# Attributes
	#

	# @!attribute [r] model
	#   The model that has validation errors.
	#
	#   @return [ActiveModel::Validations]
	attr_reader :model

	#
	# Methods
	#

	# @param model [ActiveModel::Validations, #errors] ActiveModel that is
	#   not valid and havs errors.
	def initialize(model)
		@model = model

		errors = @model.errors.full_messages.join(', ')
		translated_message = I18n.translate!(
				'metasploit.framework.errors.messages.model_invalid',
				:errors => errors
		)
		super(translated_message)
	end
end
