// To compile this program, you need to install:
//   sudo apt-get install libbluetooth-dev
// Then you can compile it with:
//   cc scanner.c -lbluetooth -o scanner


// Copyright (c) 2021 David G. Young
// Copyright (c) 2015 Damian Kołakowski. All rights reserved.
// License: BSD 3.  See: https://github.com/davidgyoung/ble-scanner

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <time.h>

#define	TRUE 1
#define	FALSE 0

struct hci_request ble_hci_request(uint16_t ocf, int clen, void* status, void* cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

//Configuration struct
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

//Used for tracking found devices and names.
typedef struct {
	char mac[18];
	char name[64];
	int count;
	} DeviceInfo;

DeviceInfo devices[1000];	
int find_or_add(const char* mac, const char* name, int deviceCount) {
    for (int i = 0; i < deviceCount; i++) {
        if (strncmp(devices[i].mac, mac, 17) == 0) {
            devices[i].count++;
            return TRUE;
        }
    }
    // not found, add new entry
    strncpy(devices[deviceCount].mac, mac, 18);
    strncpy(devices[deviceCount].name, name, 64);
    devices[deviceCount].count = 1;
    return FALSE;
}

void load_config(const char* filename, Config* config, int verbose);
int DeviceFinder(Config);

int main(){
	printf("\nQikBTSniff Starting...\n");

	Config config;
	load_config("QikBTSniff.cfg", &config, TRUE);

	//Initial scan just uses one adapter.
	int deviceCount = DeviceFinder(config);
	if ((devices[0].mac == 0) || (deviceCount < 1))
	{
		printf("Either no devices found or an error occured! End!");
		return 0;
	}
	else
	{
		printf("\n--- Devices Found ---\n");
		for (int i = 0; i < deviceCount; i++)
		{
			printf("%s  %-30s  response count: %d\n", devices[i].mac, devices[i].name, devices[i].count);
		}
	}
}

void load_config(const char* filename, Config* config, int verbose) {

	//Defaults
	config->HCI[0] = 0;
	config->HCICount = 1;
	config->initial_scan_time = 900;
	config->verbose = 0;
	config->bt_restart_timer = 600;
	config->msg_collate_time = 60;
	config->max_devices = 100;
	config->mac_filter_en = FALSE;
	strncpy(config->name_filter, "", sizeof(config->name_filter));
	config->name_filter_en = FALSE;
	config->mac_filter_en = FALSE;
	strncpy(config->mac_filter, "", sizeof(config->mac_filter));
	strncpy(config->tcp_add, "127.0.0.1:2791", sizeof(config->tcp_add));

    FILE* f = fopen(filename, "r");
    if (!f){
		printf("No config file! Using defaults.");
		return;
	}

    char line[128];
	char HCICharTemp[64];
    while (fgets(line, sizeof(line), f)) {
        char key[64], value[64];
        if (sscanf(line, "%63[^=]=%63s", key, value) == 2) {
            if (strcmp(key, "initial_scan_time") == 0)
                config->initial_scan_time = atoi(value);
            else if (strcmp(key, "verbose") == 0)
                config->verbose = atoi(value);
			else if (strcmp(key, "bt_restart_timer") == 0)
                config->bt_restart_timer = atoi(value);
			else if (strcmp(key, "msg_collate_time") == 0)
                config->msg_collate_time = atoi(value);
			else if (strcmp(key, "max_devices") == 0)
                config->max_devices = atoi(value);
            else if (strcmp(key, "mac_filter") == 0)
                strncpy(config->mac_filter, value, sizeof(config->mac_filter));
            else if (strcmp(key, "tcp_add") == 0)
                strncpy(config->tcp_add, value, sizeof(config->tcp_add));
			else if (strcmp(key, "HCI") == 0)
                strncpy(HCICharTemp, value, sizeof(HCICharTemp));
			else if (strcmp(key, "name_filter") == 0)
			strncpy(config->name_filter, value, sizeof(config->name_filter));
        }
	}

	if((strcmp("",config->mac_filter))==0){
		config->mac_filter_en = FALSE;
	}else{
		config->mac_filter_en = TRUE;
	}

	if((strcmp("",config->name_filter))==0){
		config->name_filter_en = FALSE;
	}else{
		config->name_filter_en = TRUE;
	}

	config->HCICount = 0;
	char *token = strtok(HCICharTemp, ",");
    while (token != NULL)
    {
        config->HCI[config->HCICount++] = atoi(token);
        token = strtok(NULL, ",");
    }

	printf("--------CONFIG LOADED-----------\n");
	//printf("%s",HCICharTemp);
	printf("HCI device(s):");
    for (int i = 0; i < (config->HCICount); i++)
    {
        printf("%d,", config->HCI[i]);
    }
	printf("\n");
	if (verbose > 0) {
		printf("initial_scan_time:%d\nverbose:%d\nbt_restart_timer:%d\nmsg_collate_time:%d\nmac_filter:%s\nname_filter:%s\nmax_devices:%d\ntcp_add:%s\n",
			config->initial_scan_time, config->verbose, config->bt_restart_timer, 
			config->msg_collate_time, config->mac_filter, config->name_filter, config->max_devices, config->tcp_add);
			printf("Name filter");
			if(config->name_filter_en){
				printf(" enabled");
			}else{
				printf(" disabled");
			}
			printf("\nMAC filter");
			if(config->mac_filter_en){
				 printf(" enabled");
			}else{
				printf(" disabled");
			}
			printf("\n");
	}
	printf("--------------------------------\n");

    fclose(f);
}

//function I got from Claude to turn our mac string into byte arrays that can be searched with memmem
//Purpose of this is to kick out faster if the mac doesn't even appear in the buffer.
typedef struct {
    uint8_t bytes[10][3];
    int count;
} MacFilter;

MacFilter prepare_mac_filters(Config* cfg) {
    MacFilter result = {0};
    char temp[128];
    strncpy(temp, cfg->mac_filter, sizeof(temp));
    char* token = strtok(temp, ",");
    while (token != NULL && result.count < 10) {
        int a, b, c;
        if (sscanf(token, "%02X:%02X:%02X", &a, &b, &c) == 3) {
            result.bytes[result.count][0] = c;
            result.bytes[result.count][1] = b;
            result.bytes[result.count][2] = a;
            result.count++;
        }
        token = strtok(NULL, ",");
    }
    return result;
}

int DeviceFinder(Config cfg) {

	int ret, status;
	int msgCount = 0;
	int quickMacFiltered = 0;
	unsigned now = (unsigned)time(NULL);
	unsigned EndTime = now + cfg.initial_scan_time;
	unsigned StartTime = (unsigned)time(NULL);
	
	int device = hci_open_dev(cfg.HCI[0]);
	char resetString[25];
	sprintf(resetString, "hciconfig hci%d reset", cfg.HCI[0]);
	printf("%s\n", resetString);

	//There's odd things that can happen where the adapter gets stuck. A reset can help.
	if (system(resetString) != 0) {
		printf("Reset failed\n");
	}

	int scanIntervalWindow = 0x78;
	// printf("Scan interval and window set to %0.fms", (scanIntervalWindow*0.625));
	// printf("\n");
	
	// Set BLE scan parameters.
	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type = 0x01;
	scan_params_cp.interval = htobs(scanIntervalWindow);
	scan_params_cp.window = htobs(scanIntervalWindow);
	scan_params_cp.own_bdaddr_type = 0x00; // Public Device Address (default).
	scan_params_cp.filter = 0x00; // Accept all.
	

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);

	ret = hci_send_req(device, &scan_params_rq, 1000);
	if (ret < 0) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data: ");
		return -1;
	}

	printf("Using bluetooth device %d and will scan for up to %d seconds or %d devices are found.", device, cfg.initial_scan_time,cfg.max_devices);
	printf("\n");
	// if (cfg.verbose)
	// {
	// 	if (cfg.mac_filter_en)
	// 		printf("Filtering for macs with:%s", cfg.mac_filter);
	// 	printf("\n");
	// 	if (cfg.name_filter_en)
	// 		printf("Filtering for names that start with:%s", cfg.name_filter);
	// 	printf("\n");
	// }

	// Set BLE events report mask.
	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for (i = 0; i < 8; i++) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if (ret < 0) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		return -1;
	}

	// Enable scanning.
	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0x01;	// Enable flag.
	scan_cp.filter_dup = 0x00; // Filtering disabled.
	//It seems like we'd want filtering of duplicates enabled for this scan, but even the BlueZ devs have mentioned it causing "weirdness"
	//I have tested it and at first glance, it appears to work fine, but then certain devices just won't show up.
	//I've also had a device respond to requests fine, but completely stop actually giving out any messages.
	//Our current filtering is so fast that it's not a concern anyway.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if (ret < 0) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		return -1;
	}

	// Get Results.
	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if (setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return -1;
	}

	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event* meta_event;
	le_advertising_info* info;
	int len;
	int deviceCount = 0;
	int debugSecondFilterTest = 0;
	int noTypeMatch = 0;

	MacFilter mac_filter;
	if (cfg.mac_filter_en)
		mac_filter = prepare_mac_filters(&cfg);

	while ((now < EndTime) && (deviceCount < cfg.max_devices))
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(device, &readfds);
		struct timeval tv = {0, 100000};  // must be reset each iteration
		if (select(device + 1, &readfds, NULL, NULL, &tv) > 0) {
			len = read(device, buf, sizeof(buf));
		} else {
			now = (unsigned)time(NULL);
			continue;
		}
	
		
		if (len >= HCI_EVENT_HDR_SIZE)
		{
			msgCount++;
			// A fast catch to get rid of messages that don't even have our mac.
			// Is the mac even in the buffer?
			if (cfg.mac_filter_en)
			{
				int i = 0;
				for (i = 0; i < mac_filter.count; i++)
				{
					if (memmem(buf, len, mac_filter.bytes[i], 3) != NULL)
					{
						break;
					}
				}

				if (i == mac_filter.count)
				{
					// not in the buffer
					quickMacFiltered++;
					continue;
				}
			}

			meta_event = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);
			if (meta_event->subevent == EVT_LE_ADVERTISING_REPORT)
			{
				uint8_t reports_count = meta_event->data[0];
				void *offset = meta_event->data + 1;
				int done = FALSE;
				// int filtered = FALSE;
				// while (reports_count-- && !known && !filtered)
				while (reports_count-- && !done)
				{
					info = (le_advertising_info *)offset;
					offset = info->data + info->length + 2; // We have our info, advance here instead of later in case of continue

					// Quick kick, we only want responses as we want the device name.
					if (info->evt_type != 0x04)
					{
						continue; // back to start of while loop. Check next report for the event type.
					}
					
					//This second mac filter adds processing time and will rarely be hit.
					//Chances of the mac address being in a packet, but it not being the mac of the device are very low.
					//However it *will* happen eventually, so this removes these packets.
					if (cfg.mac_filter_en)
					{
						int found = FALSE;
						for (int i = 0; i < mac_filter.count; i++)
						{
							// info->bdaddr.b is the raw MAC bytes, compare directly
							if (memcmp(&info->bdaddr.b[3], mac_filter.bytes[i], 3) == 0)
							{
								found = TRUE;
								break;
							}
						}
						if (!found)
						{
							debugSecondFilterTest++;
							continue;
						}
					}



					char addr[18];
					ba2str(&(info->bdaddr), addr);
					// Check if we already know this device.
					for (int i = 0; i < deviceCount; i++)
					{
						if (strncmp(devices[i].mac, addr, 17) == 0)
						{
							devices[i].count++;
							done = TRUE;
							break;
						}
					}
					if (done)
						continue; // Get out of our nested loop above and back to the next device.
					//NOTE: Need to clean up break/continue conditions and names

					int i = 0;
					while (i < info->length)
					{
						uint8_t len = info->data[i];
						uint8_t type = info->data[i + 1];
						if (type == 0x08 || type == 0x09)//Name
						{
							char name[32] = {0};
							int data_len = len - 1;
							for (int j = 0; j < data_len && j < 31; j++)
							{
								name[j] = info->data[i + 2 + j];
							}

							// Need to do the name filter fairly late as this is where we finally have a name.
							// At this point we filtered out all the baddies, so this shouldn't be hit too hard.
							if (cfg.name_filter_en)
							{
								if (strncmp(name, cfg.name_filter, strlen(cfg.name_filter)) != 0)
								{
									break;
								}
							}

							if (!find_or_add(addr, name, deviceCount))
							{
								deviceCount++;
								if (cfg.verbose)
								{
									printf("New!:%s - Name: %-30s - Devices found: %-3d - Time Remain: %d",
										   addr, name, deviceCount, (EndTime - now));
										   printf("\n");
								}
							}
						}
						i += len + 1; // only reached if type didn't match
					}
					
				}
			}
		}
		now = (unsigned)time(NULL);
	}


if(cfg.verbose){
	unsigned TotalTime = ((unsigned)time(NULL) - StartTime);
	unsigned MsgsPerSec = msgCount / TotalTime;
	printf("Time taken: %d seconds. \n", TotalTime);
	printf("Messages per second: %d \n", MsgsPerSec); 
	printf("Filtered by quick MAC filter: %d \n", quickMacFiltered); 
	printf("Hit second filter: %d \n", debugSecondFilterTest);
	}
printf("Devices found: %d \n", deviceCount); 

// Disable scanning.
memset(&scan_cp, 0, sizeof(scan_cp));
scan_cp.enable = 0x00;	// Disable flag.

struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
ret = hci_send_req(device, &disable_adv_rq, 1000);
if (ret < 0) {
	hci_close_dev(device);
	perror("Failed to disable scan.");
	return -1;
}

hci_close_dev(device);

return deviceCount;
}
