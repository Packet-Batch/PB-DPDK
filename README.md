# Packet Batch (DPDK)
[![Packet Batch DPDK Build Workflow](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/build.yml/badge.svg)](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/build.yml) [![Packet Batch DPDK Run Workflow](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/run.yml/badge.svg)](https://github.com/Packet-Batch/PB-DPDK/actions/workflows/run.yml)

## Description
This is a special version of Packet Batch that utilizes [the DPDK](https://dpdk.org), a kernel-bypass library. This does not use any form of Linux sockets.

With that said, the `threads` config option becomes obsolete in this special version because we use the DPDK's l-cores instead. A certain amount of ports are initialized per l-core depending on the EAL options and port mask.

This special version should be faster than all other versions of Packet Batch due to the DPDK. I was able to generate ~410K packets per second on one single l-core/port on my home server while the AF_XDP Packet Batch version generated ~1.2 million packets per second on four cores/threads. At this rate, if I utilized all four cores, the DPDK version would be able to push nearly 2 million packets per second.

## EAL Command Line
The first part of the command line arguments should be the DPDK's EAL arguments which may be found [here](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html) and ends with a `--`.

## Application-Specific Command Line
After specifying the EAL command line options and ending it with `--`, you may then add the original command line arguments from the Packet Batch Common [project](https://github.com/Packet-Batch/PB-Common).

With the above said, there are also additional command line usage for this specific application which may be found below.

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

## Building And Installing
Before building this project, you must install the DPDK and have compatible hardware. You can read the documentation [here](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) for more information.

The following commands should allow for an easy DPDK setup assuming you want to use the default configuration. You will need `meson` and `ninja`.

```bash
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

# Make and install (must be ran as root via sudo or root user itself).
sudo make
sudo make install
```

### Installation Video!
[![Click here to watch!](https://g.gflclan.com/linux-laptop-bigmode-02-02-03.png)](https://www.youtube.com/watch?v=REopw-KzaK0)

After installing, the executable is copied to the `/usr/bin/` directory which should be included in your `$PATH`. Therefore, you may use the application globally (in any directory).

For example.

```bash
pcktbatch -l 0-3 -- --queues 1 --portmask 0xff
```

## Credits
* [Christian Deacon](https://github.com/gamemann)
