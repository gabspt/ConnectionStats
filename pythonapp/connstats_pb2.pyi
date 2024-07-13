from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ConnectionStat(_message.Message):
    __slots__ = ["protocol", "l_ip", "r_ip", "l_port", "r_port", "inpps", "outpps", "inbpp", "outbpp", "inboutb", "inpoutp"]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    L_IP_FIELD_NUMBER: _ClassVar[int]
    R_IP_FIELD_NUMBER: _ClassVar[int]
    L_PORT_FIELD_NUMBER: _ClassVar[int]
    R_PORT_FIELD_NUMBER: _ClassVar[int]
    INPPS_FIELD_NUMBER: _ClassVar[int]
    OUTPPS_FIELD_NUMBER: _ClassVar[int]
    INBPP_FIELD_NUMBER: _ClassVar[int]
    OUTBPP_FIELD_NUMBER: _ClassVar[int]
    INBOUTB_FIELD_NUMBER: _ClassVar[int]
    INPOUTP_FIELD_NUMBER: _ClassVar[int]
    protocol: str
    l_ip: str
    r_ip: str
    l_port: int
    r_port: int
    inpps: int
    outpps: int
    inbpp: int
    outbpp: int
    inboutb: int
    inpoutp: int
    def __init__(self, protocol: _Optional[str] = ..., l_ip: _Optional[str] = ..., r_ip: _Optional[str] = ..., l_port: _Optional[int] = ..., r_port: _Optional[int] = ..., inpps: _Optional[int] = ..., outpps: _Optional[int] = ..., inbpp: _Optional[int] = ..., outbpp: _Optional[int] = ..., inboutb: _Optional[int] = ..., inpoutp: _Optional[int] = ...) -> None: ...

class StatsRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class StatsReply(_message.Message):
    __slots__ = ["connstat"]
    CONNSTAT_FIELD_NUMBER: _ClassVar[int]
    connstat: _containers.RepeatedCompositeFieldContainer[ConnectionStat]
    def __init__(self, connstat: _Optional[_Iterable[_Union[ConnectionStat, _Mapping]]] = ...) -> None: ...
