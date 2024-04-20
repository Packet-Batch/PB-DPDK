# Packet Batch (DPDK)
[![Packet Batch DPDK Build Workflow](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/build.yml/badge.svg)](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/build.yml) [![Packet Batch DPDK Run Workflow](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/run.yml/badge.svg)](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/run.yml)

## Description
[Packet Batch](https://github.com/Packet-Batch) is a collection of high-performance applications and tools designed for sending network packets. It serves two main purposes: penetration testing, which involves assessing network security by simulating various attacks like [Denial of Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/) (DoS); and network monitoring, which involves analyzing and inspecting network traffic.

### Features
* The ability to send multiple network packets in a chain via sequences.
* Support for sending from randomized source IPs within range(s) indicated by CIDR.
* Support for randomized payload data within a specific range in length.
* UDP, TCP, and ICMP layer 4 protocols supported.
* Optional layer 3 and 4 checksum calculation in the event you want the NIC's hardware to calculate checksums for generated outgoing packets.

### Disclaimer
I do **NOT** support using these tools maliciously or as a part of a targeted attack. I've made these tools to perform penetration tests against my own firewalls along with occasionally debugging network issues such as packets not arriving to their destination correctly.
This special version should be faster than all other versions of Packet Batch due to the DPDK. I was able to generate ~410K packets per second on one single l-core/port on my home server while the AF_XDP Packet Batch version generated ~1.2 million packets per second on four cores/threads. At this rate, if I utilized all four cores, the DPDK version would be able to push nearly 2 million packets per second.

## The DPDK
This is a special version that utilizes [The DPDK](https://www.dpdk.org/) to send network packets. The DPDK is a set of libraries for implementing user-space drivers for Network Interface Controllers (NIC). The DPDK provides you with a framework and common API for high-speed networking applications and allows for achieving a fast packet processing pipeline. As a result, this version of Packet Batch performs better than the standard version. However, it will only work more efficiently with specific hardware.

## Building And Installing
Before building this project, you must install the DPDK and have compatible hardware. You can read the documentation [here](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) for more information.

The following commands should allow for an easy DPDK setup assuming you want to use the default configuration. You will need `meson` and `ninja`.

```bash
# Install libnuma-dev if you don't have it already.
apt install -y libnuma-dev

# Clone and build the DPDK.
git clone https://github.com/DPDK/dpdk.git
cd dpdk/
meson build
cd build
ninja
sudo ninja install
sudo ldconfig
```

I've used the following commands to install `meson` and `ninja`.

```bash
sudo apt update
sudo apt install python3 python3-pip
sudo pip3 install meson # Pip3 is used because 'apt' has an outdated version of Meson usually.
sudo apt install ninja-build
```

Building and installing this project is fairly easy and just like the standard version after installing the DPDK. It includes building the Packet Batch Common repository which requires [libyaml](https://github.com/yaml/libyaml) along with my custom-made the DPDK Common [project](https://github.com/gamemann/The-DPDK-Common). As long as you use the `--recursive` flag with `git`, it should retrieve all of the required submodules automatically located in the `modules/` directory. Otherwise, you will need to go into the Common repository and execute the `git submodule update --init` command. We use `make` to build and install the application.

```bash
# Clone this repository along with its submodules.
git clone --recursive https://github.com/Packet-Batch/PB-DPDK.git

# Install build essentials/tools and needed libaries for LibYAML.
sudo apt install build-essential clang autoconf libtool

# Change the current working directory to PB-DPDK/.
cd PB-DPDK/

# Execute ./build.sh file to build and install dependencies and main project which requires sudo privileges.
# WARNING - If you don't have sudo available on your system, please look at the ./build.sh file and execute make commands as root in order.
# NOTE - You may also look at the .github/workflows/build.yml.
# NOTE - The first argument represents the amount of threads to use with make. 0 uses the amount of available threads on the system and supplying no argument uses 1 thread.
./build.sh 0

# You may use the following to clean the build. You must run this as root or sudo because of the Common's LibYAML clean.
sudo make clean
```

### Installation Video!
[![Click here to watch!](https://i.imgur.com/F45FOus.jpeg)](https://www.youtube.com/watch?v=REopw-KzaK0)

After installing, the executable is copied to the `/usr/bin/` directory which should be included in your `$PATH`. Therefore, you may use the application globally (in any directory).

For example.

```bash
pcktbatch -l 0-3 -- --queues 1 --portmask 0xff
```

## Command Line
### Basic
Basic command line usage may be found below.

```bash
Usage: pcktbatch -c <configfile> [-v -h]

-c --cfg => Path to YAML file to parse.
-l --list => Print basic information about sequences.
-v --verbose => Provide verbose output.
-h --help => Print out help menu and exit program.
```

### First Sequence Override
If you wanted to quickly send packets and don't want to create a YAML config file, you may specify command line options to override the first sequence. You must also specify the `-z` or `--cli` flag in order to do this.

The following command line options are available to override the first sequence.

```bash
--interface => The interface to send out of.
--block => Whether to enable blocking mode (0/1).
--count => The maximum amount of packets supported.
--time => How many seconds to run the sequence for maximum.
--delay => The delay in-between sending packets on each thread.
--data => The maximum amount of data (in bytes) we can send.
--trackcount => Keep track of count regardless of it being 0 (read Configuration explanation for more information) (0/1).
--l4csum => Whether to calculate the layer-4 checksum (TCP, UDP, and ICMP) (0/1).

--srcmac => The ethernet source MAC address to use.
--dstmac => The ethernet destination MAC address to use.

--minttl => The minimum IP TTL to use.
--maxttl => The maximum IP TTL to use.
--minid => The minimum IP ID to use.
--maxid => The maximum IP ID to use.
--srcip => The source IP (one range is supported in CIDR format).
--dstip => The destination IP.
--protocol => The protocol to use (TCP, UDP, or ICMP).
--tos => The IP TOS to use.
--l3csum => Whether to calculate the IP header checksum or not (0/1).

--usrcport => The UDP source port.
--udstport => The UDP destination port.

--tsrcport => The TCP source port.
--tdstport => The TCP destination port.
--tsyn => Set the TCP SYN flag (0/1).
--tack => Set the TCP ACK flag (0/1).
--tpsh => Set the TCP PSH flag (0/1).
--trst => Set the TCP RST flag (0/1).
--tfin => Set the TCP FIN flag (0/1).
--turg => Set the TCP URG flag (0/1).

--pmin => The minimum payload data.
--pmax => The maximum payload data.
--pstatic => Use static payload (0/1).
--pexact => The exact payload string.
--pfile => Whether to parse a file as the 'pexact' string instead.
--pstring => Parse the 'pexact' string or file as a string instead of hexadecimal.
```

### The DPDK
The first part of the command line arguments should be the DPDK's EAL arguments which may be found [here](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html) and ends with a `--`.

After specifying the EAL command line options and ending it with `--`, you may then add the original command line arguments above.

With the above said, there is also additional command line usage for this version which may be found below.

```
--portmask => The port mask to use with the DPDK application.
--queues => The amount of TX queues to setup per port (default and recommended is 1).
--promisc => Whether to enable promiscuous mode on all enabled ports.
--burstsize => The max TX buffer burst size (default 32).
--useall => Load balances all ports and TX queues to l-cores in round-robin fashion and vice versa.
```

Examples may be found below.

```bash
# Sets up 4 l-cores (IDs 0 - 3) along with enabling all ports. 1 TX queue per port is initialized.
pcktbatch -l 0-3 -- -c /etc/pcktbatch/test01.yaml --queues 1 --portmask 0xff

# Sets up 1 l-core (ID 0) along with enabling the first port. 1 TX queue is initialized.
pcktbatch -l 0 -- -c /etc/pcktbatch/test01.yaml --queues 1 --portmask 0x01
```

## Configuration File
If you want to use more than one sequence or more control, you will need to specify sequences inside of a config file using the [YAML syntax](https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html). Please see the following for an explanation.

```yaml
# The interface to send packets out of.
interface: myinterface

sequences:
    seq01:
        # An array of other configs to include before this sequence. WARNING - If this is used, you must write this at the beginning of the sequence like this example. Otherwise, unexpected results will occur (e.g. the current sequence will be overwritten). This is empty by default and only showing as an example.
        includes:
            - /etc/pcktbatch/include_one.yaml
            - /etc/pcktbatch/include_two.yaml

        # If set, will use a specific interface for this sequence. Otherwise, uses the default interface specified at the beginning of the config.
        interface: NULL

        # If true, future sequences will wait until this one finishes before executing.
        block: true

        # The maximum packets this sequence can produce before terminating.
        count: 0

        # The maximum bytes this sequence can produce before terminating.
        data: 0

        # How long in seconds this sequence can go on before terminating.
        time: 0

        # The delay between sending packets on each thread in microseconds.
        delay: 1000000

        # If true, even if 'count' is set to 0, the program will keep a packet counter inside of each thread. As of right now, a timestamp (in seconds) and a packet counter is used to generate a seed for randomness within the packet. If you want true randomness with every packet and not with each second, it is recommended you set this to true. Otherwise, this may result in better performance if kept set to false.
        trackcount: false 
        
        # Ethernet header options.
        eth:
            # The source MAC address. If not set, the program will retrieve the MAC address of the interface we are binding to (the "interface" value).
            #srcmac: NULL

            # The destination MAC address. If not set, the program will retrieve the default gateway's MAC address.
            #dstmac: NULL
        
        # IP header options.
        ip:
            # Source ranges in CIDR format. By default, these aren't set, but I wanted to show an example anyways. These will be used if 'srcip' is not set.
            ranges:
                - 172.16.0.0/16
                - 10.60.0.0/24
                - 192.168.30.0/24
            
            # The source IPv4 address. If not set, you will need to specify source ranges in CIDR format like the above. If no source IP ranges are set, a warning will be outputted to `stderr` and 127.0.0.1 (localhost) will be used.
            #srcip: NULL

            # The destination IPv4 address. If not set, the program will output an error. We require a value here. Otherwise, the program will shutdown.
            #dstip: NULL

            # The IP protocol to use. At the moment, the only supported values are udp, tcp, and icmp.
            protocol: udp

            # The Type-Of-Service field (8-bit integer).
            tos: 0
            
            # The Time-To-Live field (8-bit integer). For static, set min and max to the same value.
            ttl:
                # Each packet generated will pick a random TTL. This is the minimum value within that range.
                min: 0

                # Each packet generated will pick a random TTL This is the maximum value within that range.
                max: 0
            
            # The ID field. For static, set min and max to the same value.
            id:
                # Each packet generated will pick a random ID. This is the minimum value within that range.
                min: 0

                # Each packet generated will pick a random ID. This is the maximum value within that range.
                max: 0

            # If true, we will calculate the IP header's checksum. If your NIC supports checksum offload with the IP header, disabling this option may improve performance within the program.
            csum: true

        # If true, we will calculate the layer-4 protocol checksum (UDP, TCP, and ICMP).
        l4csum: true

        # UDP header options.
        udp:
            # The source port. If 0, the program will generate a random number between 1 and 65535.
            srcport: 0

            # The destination port. If 0, the program will generate a random number between 1 and 65535.
            dstport: 0

        # TCP header options.
        tcp:
            # The source port. If 0, the program will generate a random number between 1 and 65535.
            srcport: 0

            # The destination port. If 0, the program will generate a random number between 1 and 65535.
            dstport: 0

            # If true, will set the TCP SYN flag.
            syn: false

            # If true, will set the TCP ACK flag.
            ack: false
        
            # If true, will set the TCP PSH flag.
            psh: false

            # If true, will set the TCP RST flag.
            rst: false

            # If true, will set the TCP FIN flag.
            fin: false

            # If true, will set the TCP URG flag.
            urg: false

        # ICMP header options.
        icmp:
            # The code to use with the ICMP packet.
            code: 0

            # The type to use with the ICMP packet.
            type: 0

        # Payload options.
        payload:
            # Random payload generation/length.
            length:
                # The minimum payload length in bytes (payload is randomly generated).
                min: 0

                # The maximum payload length in bytes (payload is randomly generated).
                max: 0

            # If true, the application will only generate one payload per thread between the minimum and maximum lengths and generate the checksums once. In many cases, this will result in a huge performance gain because generating random payload per packet consumes a lot of CPU cycles depending on the payload length.
            isstatic: false

            # If true, the application will read data from the file 'exact' (below) is set to. The data within the file should be in the same format as the 'exact' setting without file support which is hexadecimal and separated by a space (e.g. "FF FF FF FF 59").
            isfile: false

            # If true, will parse the payload (either in 'exact' or the file within 'exact') as a string instead of hexadecimal.
            isstring: false

            # If a string, will set the payload to exactly this value. Each byte should be in hexadecimal and separated by a space. For example: "FF FF FF FF 59" (5 bytes of payload data).
            #exact: NULL
```

There are configuration examples [here](https://github.com/Packet-Batch/PB-Tests).

**NOTE** - The default config path is `/etc/pcktbatch/pcktbatch.yaml`. This may be changed via the `-c` and `--cfg` flags as explained under the Command Line Usage section below.

## Credits
* [Christian Deacon](https://github.com/gamemann)
