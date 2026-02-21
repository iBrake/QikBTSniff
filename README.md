# QikBTSniff
Fast bluetooth advertising sniffer and handler.

**What is this?**

QikBTSniff is an application designed to retrieve Bluetooth advertising packets. It was specifically designed to work with sensors that put data in the advertising packet so that they can be read passively, but you're free to do what you want with it.

**Why?**

Current options for reading data from these sensors have a number of issues.

1. *Speed*

The Bluetooth advertising spectrum can be incredibly busy and low power sensors might only output a packet every ten seconds. To ensure a packet isn't missed, potentially 100s of packets a second need to be filtered to ensure we get the data we require. QikBTSniff was designed with this in mind and is written entirely in C/C++.
Long term tests with conventional JavaScript and python libraries have showed frequent gaps of up to 15 minutes between received packets from a sensor sending once every 10 seconds. This means 90 packets missed!
While that's an extreme example, it's clear that we can do better.

2. *Sensor Battery Life Vs Information*

The first issue is that the majority of the current libraries will use "active" Bluetooth scanning. This means for a full received packet, we have to respond to the sensors advertising packet, and then have it respond back. This duplicates the amount of packets the sensor has to send and has effects on battery life, however it also effects reliability as we need three packets in total to be successful before we have the full data required.
QikBTSniff first uses active mode to scan for sensors and saves the information about the sensor. After the initial scan, QikBTSniff switches to passive scanning, which just requires receiving a packet from the sensor. It then uses the initial information it gathered so it can collate the sensors variable information with the static. This gives the advantages of both active and passive scanning.

3. *Bluetooth hardware can be flakey*
One of the issues with current Bluetooth AD scanners is that they handle failure very poorly. In particular, some that require external daemons might need an entire application to be restarted, or even Linux itself, before being able to revive an adapter. QikBTSniff runs each Bluetooth scanning process in a separate thread that is restarted periodically. This means even "silent failures" should fix themselves.

4. *Easy incorporation of Bluetooth sensors to other projects*
   
The majority of the current libraries will use "active" Bluetooth scanning. This means for a full received packet, we have to respond to the sensors advertising packet, and then have it respond back. This duplicates the amount of packets the sensor has to send and has effects on battery life, however it also effects reliability as we need three packets in total to be successful before we have the full data required.
QikBTSniff first uses active mode to scan for sensors and saves the information about the sensor. After the initial scan, QikBTSniff switches to passive scanning, which just requires receiving a packet from the sensor. It then uses the initial information it gathered so it can collate the sensors variable information with the static. This gives the advantages of both active and passive scanning.

3. *Bluetooth hardware can be flakey*
   
One of the issues with current Bluetooth AD scanners is that they handle failure very poorly. In particular, some that require external daemons might need an entire application to be restarted, or even Linux itself, before being able to revive an adapter. QikBTSniff runs each Bluetooth scanning process in a separate thread that is restarted periodically. This means even "silent failures" should fix themselves.

4. *Easy incorporation of Bluetooth sensors to other projects*
   
While you can write something simple in Python to start listening for Bluetooth advertising packets, the information above gives a few of the multitude of reasons why you shouldn't. QikBTSniff collates the advertising packets and periodically sends them over TCP. This means any application can simply open a TCP port and start receiving reliable Bluetooth advertising information without worrying about the hardware side.
This collation of the information also makes it much easier to process for the receiving application as well as the data is structured in an easy to read JSON for each sensor QikBTSniff is monitoring.

**Current state?**

Currently QikBTSniff is at V0.01, this version will currently preform the active scan session as per the settings in the configuration file.
If you'd like to try this, the latest compiled version is in the bin folder. Just download QikBTSniff and QikBTSniff.cfg to the same folder on your Linux machine and run with ./QikBTSniff 
Currently only tested on Ubuntu 24.04, but the main dependencies have been included with Ubuntu since 14.
The application needs su due to interacting with HCI.
By default, it will look for any sensor using HCI0 and scan for ten minutes. After ensuring that it runs fine with the defaults, you can try altering the cfg file to your liking. MAC filtering is highly desirable as it allows us to clear the queue quicker and get packets from our desired sensors faster. All the options are explained in the cfg file.

**Thanks**

The basic Bluetooth code for QikBTSniff was copied/inspired/stolen from https://github.com/davidgyoung/ble-scanner
A copy of the original scanner.c is in the docs folder.
