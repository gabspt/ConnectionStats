# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import connstats_pb2 as connstats__pb2


class StatsServiceStub(object):
    """The greeting service definition.
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.CollectStats = channel.unary_unary(
                '/connstatsprotobuf.StatsService/CollectStats',
                request_serializer=connstats__pb2.StatsRequest.SerializeToString,
                response_deserializer=connstats__pb2.StatsReply.FromString,
                )


class StatsServiceServicer(object):
    """The greeting service definition.
    """

    def CollectStats(self, request, context):
        """Sends a connection stats
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_StatsServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'CollectStats': grpc.unary_unary_rpc_method_handler(
                    servicer.CollectStats,
                    request_deserializer=connstats__pb2.StatsRequest.FromString,
                    response_serializer=connstats__pb2.StatsReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'connstatsprotobuf.StatsService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class StatsService(object):
    """The greeting service definition.
    """

    @staticmethod
    def CollectStats(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/connstatsprotobuf.StatsService/CollectStats',
            connstats__pb2.StatsRequest.SerializeToString,
            connstats__pb2.StatsReply.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
