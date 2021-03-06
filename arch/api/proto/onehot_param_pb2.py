# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: onehot-param.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='onehot-param.proto',
  package='com.webank.ai.fate.common.mlmodel.buffer',
  syntax='proto3',
  serialized_pb=_b('\n\x12onehot-param.proto\x12(com.webank.ai.fate.common.mlmodel.buffer\"G\n\x07\x43olsMap\x12\x0e\n\x06values\x18\x01 \x03(\t\x12\x19\n\x11\x65ncoded_variables\x18\x02 \x03(\t\x12\x11\n\tdata_type\x18\x03 \x01(\t\"\xc3\x01\n\x0bOneHotParam\x12R\n\x07\x63ol_map\x18\x01 \x03(\x0b\x32\x41.com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.ColMapEntry\x1a`\n\x0b\x43olMapEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12@\n\x05value\x18\x02 \x01(\x0b\x32\x31.com.webank.ai.fate.common.mlmodel.buffer.ColsMap:\x02\x38\x01\x42\x12\x42\x10OneHotParamProtob\x06proto3')
)




_COLSMAP = _descriptor.Descriptor(
  name='ColsMap',
  full_name='com.webank.ai.fate.common.mlmodel.buffer.ColsMap',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='values', full_name='com.webank.ai.fate.common.mlmodel.buffer.ColsMap.values', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='encoded_variables', full_name='com.webank.ai.fate.common.mlmodel.buffer.ColsMap.encoded_variables', index=1,
      number=2, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data_type', full_name='com.webank.ai.fate.common.mlmodel.buffer.ColsMap.data_type', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=64,
  serialized_end=135,
)


_ONEHOTPARAM_COLMAPENTRY = _descriptor.Descriptor(
  name='ColMapEntry',
  full_name='com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.ColMapEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.ColMapEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='value', full_name='com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.ColMapEntry.value', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=_descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001')),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=237,
  serialized_end=333,
)

_ONEHOTPARAM = _descriptor.Descriptor(
  name='OneHotParam',
  full_name='com.webank.ai.fate.common.mlmodel.buffer.OneHotParam',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='col_map', full_name='com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.col_map', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_ONEHOTPARAM_COLMAPENTRY, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=138,
  serialized_end=333,
)

_ONEHOTPARAM_COLMAPENTRY.fields_by_name['value'].message_type = _COLSMAP
_ONEHOTPARAM_COLMAPENTRY.containing_type = _ONEHOTPARAM
_ONEHOTPARAM.fields_by_name['col_map'].message_type = _ONEHOTPARAM_COLMAPENTRY
DESCRIPTOR.message_types_by_name['ColsMap'] = _COLSMAP
DESCRIPTOR.message_types_by_name['OneHotParam'] = _ONEHOTPARAM
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ColsMap = _reflection.GeneratedProtocolMessageType('ColsMap', (_message.Message,), dict(
  DESCRIPTOR = _COLSMAP,
  __module__ = 'onehot_param_pb2'
  # @@protoc_insertion_point(class_scope:com.webank.ai.fate.common.mlmodel.buffer.ColsMap)
  ))
_sym_db.RegisterMessage(ColsMap)

OneHotParam = _reflection.GeneratedProtocolMessageType('OneHotParam', (_message.Message,), dict(

  ColMapEntry = _reflection.GeneratedProtocolMessageType('ColMapEntry', (_message.Message,), dict(
    DESCRIPTOR = _ONEHOTPARAM_COLMAPENTRY,
    __module__ = 'onehot_param_pb2'
    # @@protoc_insertion_point(class_scope:com.webank.ai.fate.common.mlmodel.buffer.OneHotParam.ColMapEntry)
    ))
  ,
  DESCRIPTOR = _ONEHOTPARAM,
  __module__ = 'onehot_param_pb2'
  # @@protoc_insertion_point(class_scope:com.webank.ai.fate.common.mlmodel.buffer.OneHotParam)
  ))
_sym_db.RegisterMessage(OneHotParam)
_sym_db.RegisterMessage(OneHotParam.ColMapEntry)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('B\020OneHotParamProto'))
_ONEHOTPARAM_COLMAPENTRY.has_options = True
_ONEHOTPARAM_COLMAPENTRY._options = _descriptor._ParseOptions(descriptor_pb2.MessageOptions(), _b('8\001'))
# @@protoc_insertion_point(module_scope)
