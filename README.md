# ConnectionStats
ebpf-go project to measure network connection statistics. TFM

# Requirements
Inside Requirements folder can be found the installed libraries and dependencies to run the programs in Ubuntu 22.04.3 LTS

To reinstall them in your system use the following comands:

dpkg --get-selections < ubuntu_installed_packages.txt

apt-get dselect-upgrade

pip install -r requirements_python.txt

with the go.mod and go.sum files copied in the environments run:
go mod download

# Run the programs
To run the ebpf probe go to the cmd folder, you can select the interface to attach the ebpf program using the interface option as shown below, by default is enp0s3. Inside cmd folder run:

sudo go run connstats.go [options]

current options are:

-i <interface> : interface to attach the ebpf program, by default is enp0s8
-t <time_aggregation_level> : time aggregation level for the eviction of flowstats hash map by the userspace in seconds, by default is 5 seconds

To run the python program go to pythonapp folder, use the server_ip option to enter the ip of the machine running the probe. Know you can also copy the pythonapp folder to a remote location that has connectivity with the machine running the probe. Inside pythonapp folder run:

python3 main.py [options]

current options are:

--server <server_ip> : ip of the machine running the probe, mandatory option

--rtime <refresh_time> : refresh time in seconds to collect the statistics from the probe, 10 sec by default

example: python3 main.py --server 192.168.1.204 --rtime 7
