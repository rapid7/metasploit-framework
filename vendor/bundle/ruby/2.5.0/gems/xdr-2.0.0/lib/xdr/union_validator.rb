class XDR::UnionValidator < ActiveModel::Validator
  def validate(union)
    # validate a discriminant is set
    # validate the arm is compatible with the set discriminant
    # TODO
  end
end