#ifndef BTSCAN_H
#define BTSCAN_H


#include <stdlib.h>
#include <unistd.h> // I/O primitives (read for the device buffer). 
#include <time.h> //Calculating scan time.
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <errno.h> //Mainly for getting errno from HCI libs for perror.#include <stdlib.h>
#include <unistd.h> // I/O primitives (read for the device buffer). 
#include <time.h> //Calculating scan time.


#define	TRUE 1
#define	FALSE 0

//structs
typedef struct {
	int HCI[16];
	int HCICount;
	int max_devices;
	int initial_scan_time;
	int verbose;
	char mac_filter[64];
	int mac_filter_en;
	int bt_restart_timer;
	int msg_collate_time;
	char tcp_add[25];
	char name_filter[64];
	int  name_filter_en;
} Config;

struct hci_request ble_hci_request(uint16_t ocf, int clen, void* status, void* cparam);


//Used for tracking found devices and names.
typedef struct {
	char mac[18];
	char name[64];
	int count;
} DeviceInfo;
extern DeviceInfo devices[1000]; //Created in BTScan.c, extern means created elsewhere.

//Used for our fast mac filter.
typedef struct {
	uint8_t bytes[10][3];
	int count;
} MacFilter;
MacFilter prepare_mac_manu_filters(Config*);

//used later for device filter during passive scanning.
typedef struct {
	uint8_t bytes[100][6];
	int count;
} DeviceMacsToFind;

DeviceMacsToFind build_mac_dev_filters(DeviceInfo*, int);


int DeviceFinder(Config);
int find_or_add(const char*, const char*, int);
int AdFinder(int, DeviceMacsToFind, int, int, int);
#endif