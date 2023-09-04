from __future__ import print_function

import logging
import time
import ipaddress
import pandas as pd


import grpc
import connstats_pb2
import connstats_pb2_grpc

def convert_to_ipv4(ipv6_address):
    try:
        ipv6 = ipaddress.IPv6Address(ipv6_address)
        if ipv6.ipv4_mapped:
            ipv4_address = ipv6.ipv4_mapped
            return str(ipv4_address)
        else:
            return str(ipv6)  # If is not mapped, return the original IPv6 as string
    except ipaddress.AddressValueError:
        return "Invalid IP address"

def run():
   
    print("Will try to start ...")

    

    with grpc.insecure_channel("192.168.1.204:50051") as channel:
        stub = connstats_pb2_grpc.StatsServiceStub(channel)
        
        while True:
            response = stub.CollectStats(connstats_pb2.StatsRequest())
            print("Server response received")
            #print(response.connstat)
            #response = stub.SayHelloAgain(helloworld_pb2.HelloRequest(name='Gaby'))
            # print("Greeter client received: " + response.message)

            # Crear listas vacías para almacenar los datos
            Hash = []
            Protocol = []
            A = []
            #a = []
            B = []
            #b = []
            Inpps = []
            Outpps = []
            InBpp = []
            OutBpp = []
            InBoutB = []
            InPoutP = []
            # usar response para calcular las estadisticas
            for connection in response.connstat:
                Hash.append(connection.hash)
                Protocol.append(connection.proto)
                A.append(f"{convert_to_ipv4(connection.a_ip)}:{connection.a_port}")
                B.append(f"{convert_to_ipv4(connection.b_ip)}:{connection.b_port}")

                time_diff = (connection.ts_fin - connection.ts_ini) / 1000000000
                if time_diff > 0:
                    inpps = connection.packets_in / time_diff  
                    outpps = connection.packets_out / time_diff   
                else:
                    inpps = 0.0
                    outpps = 0.0
                Inpps.append(inpps)
                Outpps.append(outpps)
                
                if connection.packets_in > 0:
                    inBpp = connection.bytes_in / connection.packets_in
                else:
                    inBpp = 0.0
                InBpp.append(inBpp)
                
                if connection.packets_out > 0:
                    outBpp = connection.bytes_out / connection.packets_out
                    inPoutP = connection.packets_in / connection.packets_out
                else:
                    outBpp = 0.0
                    inPoutP = 0.0
                OutBpp.append(outBpp)
                InPoutP.append(inPoutP)

                if connection.bytes_out > 0:
                    inBoutB = connection.bytes_in / connection.bytes_out
                else:
                    inBoutB = 0.0
                InBoutB.append(inBoutB)

                # print(f"A: {convert_to_ipv4(connection.a_ip)}:{connection.a_port}, B: {convert_to_ipv4(connection.b_ip)}:{connection.b_port} ", end="")
                # print(f"inpps: {inpps:.2f} ", end="")
                # print(f"outpps: {outpps:.2f} ", end="")
                # print(f"inBpp: {inBpp:.2f} ", end="")
                # print(f"outBpp: {outBpp:.2f} ", end="")
                # print(f"inBoutB: {inBoutB:.2f} ", end="")
                # print(f"inPoutP: {inPoutP:.2f} ")

            df = pd.DataFrame({
                'Hash': Hash,
                'Protocol': Protocol,
                'A': A,
                'B': B,
                'inpps': inpps,
                'outpps': outpps,
                'inBpp': inBpp,
                'outBpp': outBpp,
                'inBoutB': inBoutB,
                'inPoutP': inPoutP
            })
            df.set_index('Hash', inplace=True)

            
            print(df)  
            print("")  

            # Guardar el DataFrame en un archivo CSV
            df.to_csv('datos.csv', index=False)  
               

            time.sleep(6)


if __name__ == "__main__":
    logging.basicConfig()
    run()
