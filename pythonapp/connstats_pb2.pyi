from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ConnectionStat(_message.Message):
    __slots__ = ["a_ip", "b_ip", "a_port", "b_port", "packets_in", "packets_out", "ts_ini", "ts_fin", "bytes_in", "bytes_out"]
    A_IP_FIELD_NUMBER: _ClassVar[int]
    B_IP_FIELD_NUMBER: _ClassVar[int]
    A_PORT_FIELD_NUMBER: _ClassVar[int]
    B_PORT_FIELD_NUMBER: _ClassVar[int]
    PACKETS_IN_FIELD_NUMBER: _ClassVar[int]
    PACKETS_OUT_FIELD_NUMBER: _ClassVar[int]
    TS_INI_FIELD_NUMBER: _ClassVar[int]
    TS_FIN_FIELD_NUMBER: _ClassVar[int]
    BYTES_IN_FIELD_NUMBER: _ClassVar[int]
    BYTES_OUT_FIELD_NUMBER: _ClassVar[int]
    a_ip: str
    b_ip: str
    a_port: int
    b_port: int
    packets_in: int
    packets_out: int
    ts_ini: int
    ts_fin: int
    bytes_in: int
    bytes_out: int
    def __init__(self, a_ip: _Optional[str] = ..., b_ip: _Optional[str] = ..., a_port: _Optional[int] = ..., b_port: _Optional[int] = ..., packets_in: _Optional[int] = ..., packets_out: _Optional[int] = ..., ts_ini: _Optional[int] = ..., ts_fin: _Optional[int] = ..., bytes_in: _Optional[int] = ..., bytes_out: _Optional[int] = ...) -> None: ...

class StatsRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class StatsReply(_message.Message):
    __slots__ = ["connstat"]
    CONNSTAT_FIELD_NUMBER: _ClassVar[int]
    connstat: _containers.RepeatedCompositeFieldContainer[ConnectionStat]
    def __init__(self, connstat: _Optional[_Iterable[_Union[ConnectionStat, _Mapping]]] = ...) -> None: ...
