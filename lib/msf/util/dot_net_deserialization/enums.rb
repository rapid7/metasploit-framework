module Msf
module Util
module DotNetDeserialization
module Enums

#
# .NET Serialization Enumerations
#
BinaryTypeEnum = {
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/054e5c58-be21-4c86-b1c3-f6d3ce17ec72
  Primitive: 0,
  String: 1,
  Object: 2,
  SystemClass: 3,
  Class: 4,
  ObjectArray: 5,
  StringArray: 6,
  PrimitiveArray: 7
}

PrimitiveTypeEnum = {
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/4e77849f-89e3-49db-8fb9-e77ee4bc7214
  Boolean: 1,
  Byte: 2,
  Char: 3,
  Decimal: 5,
  Double: 6,
  Int16: 7,
  Int32: 8,
  Int64: 9,
  SByte: 10,
  Single: 11,
  TimeSpan: 12,
  DateTime: 13,
  UInt16: 14,
  UInt32: 15,
  UInt64: 16,
  Null: 17,
  String: 18
}

RecordTypeEnum = {
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/954a0657-b901-4813-9398-4ec732fe8b32
  SerializedStreamHeader: 0,
  ClassWithId: 1,
  SystemClassWithMembers: 2,
  ClassWithMembers: 3,
  SystemClassWithMembersAndTypes: 4,
  ClassWithMembersAndTypes: 5,
  BinaryObjectString: 6,
  BinaryArray: 7,
  MemberPrimitiveTyped: 8,
  MemberReference: 9,
  ObjectNull: 10,
  MessageEnd: 11,
  BinaryLibrary: 12,
  ObjectNullMultiple256: 13,
  ObjectNullMultiple: 14,
  ArraySinglePrimitive: 15,
  ArraySingleObject: 16,
  ArraySingleString: 17,
  MethodCall: 21,
  MethodReturn: 22
}

end
end
end
end
