// To compile this program, you may need to install:
//   sudo apt-get install libbluetooth-dev
// Then you can compile it with:
//   cc QikBTSniff.c -lbluetooth -o QikBTSniff


// Copyright (c) 2026 iBrake
// See: https://github.com/iBrake/QikBTSniff

#include <stdlib.h>
#include <time.h> //Calculating scan time.
#include "BTScan.h"

#define	TRUE 1
#define	FALSE 0


void load_config(const char* filename, Config* config, int verbose);


int main(){
	printf("\nQikBTSniff Starting...\n");

	Config config;
	load_config("QikBTSniff.cfg", &config, TRUE);

	//Initial scan just uses one adapter.
	int deviceCount = DeviceFinder(config);
	if (deviceCount < 1)
	{
		printf("Either no devices found or an error occured! End!\n");
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

