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
   
    print("Try to start ...")

    with grpc.insecure_channel("192.168.1.204:50051") as channel:
        stub = connstats_pb2_grpc.StatsServiceStub(channel)
        
        while True:
            response = stub.CollectStats(connstats_pb2.StatsRequest())
            print("Server response received")

            # Crear listas vacías para almacenar los datos estadísticos
            Protocol = []
            Local = []
            Remote = []
            PacketsIn = []
            PacketsOut = []
            BytesIn = []
            BytesOut = []
            TsStart = []
            TsCurrent = []
            Inpps = []
            Outpps = []
            InBpp = []
            OutBpp = []
            InBoutB = []
            InPoutP = []
            # usar response para calcular las estadisticas
            for connection in response.connstat:
                Protocol.append(connection.protocol)
                Local.append(f"{convert_to_ipv4(connection.l_ip)}:{connection.l_port}")
                Remote.append(f"{convert_to_ipv4(connection.r_ip)}:{connection.r_port}")
                PacketsIn.append(connection.packets_in)
                PacketsOut.append(connection.packets_out)
                BytesIn.append(connection.bytes_in)
                BytesOut.append(connection.bytes_out)
                TsStart.append(connection.ts_start)
                TsCurrent.append(connection.ts_current)
                
                time_diff = (connection.ts_current - connection.ts_start) / 1000000000
                if time_diff> 0:
                    Inpps.append(connection.packets_in / time_diff)
                    Outpps.append(connection.packets_out / time_diff)
                else:
                    #print this connection attributes in one line for debug   
                    print("connection.protocol: ", connection.protocol)
                    print("connection.l_ip: ", connection.l_ip)
                    print("connection.l_port: ", connection.l_port)
                    print("connection.r_ip: ", connection.r_ip)
                    print("connection.r_port: ", connection.r_port)
                    print("connection.packets_in: ", connection.packets_in)
                    print("connection.packets_out: ", connection.packets_out)
                    print("connection.ts_start: ", connection.ts_start)
                    print("connection.ts_current: ", connection.ts_current)
                 
                    Inpps.append(0)
                    Outpps.append(0)
                
                if connection.packets_in > 0:
                    InBpp.append(connection.bytes_in / connection.packets_in)
                else:
                    InBpp.append(0)
                
                if connection.packets_out > 0:
                    OutBpp.append(connection.bytes_out / connection.packets_out)
                    InPoutP.append(connection.packets_in / connection.packets_out)
                    InBoutB.append(connection.bytes_in / connection.bytes_out)
                else:
                    OutBpp.append(0)
                    InPoutP.append(0)
                    InBoutB.append(0)

            dfStats = pd.DataFrame({
                'Protocol': Protocol,
                'Local': Local,
                'Remote': Remote,
                'inpps': Inpps,
                'outpps': Outpps,
                'inBpp': InBpp,
                'outBpp': OutBpp,
                'inBoutB': InBoutB,
                'inPoutP': InPoutP
            })

            df = pd.DataFrame({
                'Protocol': Protocol,
                'Local': Local,
                'Remote': Remote,
                'PacketsIN': PacketsIn,
                'PacketsOUT': PacketsOut,
                'BytesIN': BytesIn,
                'BytesOUT': BytesOut,
                'TsStart': TsStart,
                'TsCurrent': TsCurrent
            })
            #df.set_index('Hash', inplace=True)

            
            print(dfStats)  
            print("")  

            # Guardar el DataFrame en un archivo CSV
            dfStats.to_csv('datos.csv', index=False)  
               

            time.sleep(7)


if __name__ == "__main__":
    logging.basicConfig()
    run()
