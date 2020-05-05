# Gemini
dpdk AE prototype

## Directory Layout
```
root
|-- CMakeLists.txt                       # Top-level CMakeLists
|-- CMakeSettings.json                   # CMake Settings for Visual Studio
|-- include                              # All global include files 
|   |-- common                           # Includes shared by all modules
|   |   `-- [common.include.file]
|   `-- seadp_client                     # Includes introduced by SEADP Client
|       `-- [seadp_client.include.files]
|   `-- tldk                             # Includes introduced by TLDK
|       `-- [tle.include.files]
|-- lib                                  # All non-well-known Static libraries
|   |-- tle.libs.a
|   `-- [other.libs.a]
|-- bbr_congestion_control               # BBR Module
|   |-- CMakeLists.txt                   # Project-wide CMakeLists
|   |-- [local.include.files]
|   `-- [other.src.files]
|-- main                                 # Main Program Module
|   |-- CMakeLists.txt                   # Project-wide CMakeLists
|   |-- main.c	                         # Program Entry Point
|   |-- [local.include.files]
|   `-- [other.src.files]
|-- seadp_client                         # SEADP Client Module
|   |-- CMakeLists.txt                   # Project-wide CMakeLists
|   |-- [local.include.files]
|   `-- [other.src.files]
`-- README.md
```

## Building Project
### Configure DPDK
See [DPDK Documentation](http://doc.dpdk.org/guides/linux_gsg/build_dpdk.html) for details.
#### 1. Install required libraries
For CentOS
```bash
yum install meson.noarch numactl-devel.x86_64
```
#### 2. Get DPDK 18.11
Download DPDK 18.11 source from [DPDK Download](http://core.dpdk.org/download/).

#### 3. Uncompress DPDK and Browse Sources
```bash
tar Jxf dpdk-<version>.tar.xz
cd dpdk-<version>
```

#### 3. Compiling and Installing DPDK System-wide
```bash
meson build
cd build
ninja-build
ninja-build install
echo /usr/local/lib64/ > /etc/ld.so.conf.d/dpdk-x86_64.conf
ldconfig
```
echo /usr/local/lib/x86_64-linux-gnu/ > /etc/ld.so.conf.d/dpdk-x86_64.conf

### Generate CMake
Out of source build is recommended.
```bash
cd <path-to-source>
mkdir build
cd build
cmake -G "Ninja"  -DCMAKE_BUILD_TYPE="Debug" ../
```
"\<type\>" can be "Debug", "Release", "RelWithDebInfo" or "MinSizeRel".
```
CMAKE_C_FLAGS_DEBUG = -g
CMAKE_C_FLAGS_RELEASE = -O3 -DNDEBUG
CMAKE_C_FLAGS_RELWITHDEBINFO = -O2 -g -DNDEBUG
CMAKE_C_FLAGS_MINSIZEREL = -Os -DNDEBUG
```
### Build
For Ninja
```bash
ninja-build
```
./main/dpdk-test -c 0xfff -n 4 -- -p 3