from __future__ import print_function

import logging
import time

import grpc
import connstats_pb2
import connstats_pb2_grpc


def run():
   
    # print("Will try to greet world ...")
    with grpc.insecure_channel("localhost:50051") as channel:
        stub = connstats_pb2_grpc.StatsServiceStub(channel)
        
        while True:
            response = stub.CollectStats(connstats_pb2.StatsRequest())
            # print("Greeter client received: " + response.message)
            #response = stub.SayHelloAgain(helloworld_pb2.HelloRequest(name='Gaby'))
            # print("Greeter client received: " + response.message)

            # usar response para calcular las estadisticas
            for connection in response.connstat:
                print(f"Connection: A_IP={connection.a_ip}, B_IP={connection.b_ip}, Packets In={connection.packets_in}, Packets Out={connection.packets_out}")

            time.sleep(5)


if __name__ == "__main__":
    logging.basicConfig()
    run()
