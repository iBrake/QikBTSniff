// To compile this program, you may need to install:
//   sudo apt-get install libbluetooth-dev
// Then you can compile it with:
//   cc QikBTSniff.c -lbluetooth -o QikBTSniff


// Copyright (c) 2026 iBrake
// See: https://github.com/iBrake/QikBTSniff
#include <stdlib.h>
#include <time.h> //Calculating scan time.
#include "BTScan.h"
#include "ThreadedQueue.h" // Our queue stuff
#include <thread> //Std stuff for the thread queue
#include <vector> //Std stuff for the thread queue
//Below included for json formatting.
//#include <cstdio>
//Below for TCP send
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define	TRUE 1
#define	FALSE 0

//Below two structs for our data collating.
typedef struct {
	uint16_t uuid;
	uint8_t  data[31];
	uint8_t  data_len;
} UUIDPayload;

typedef struct {
	uint8_t     mac[6];
	UUIDPayload payloads[12];
	int         payload_count;
	time_t      last_seen;
} DeviceRecord;


void load_config(const char* filename, Config* config, int verbose);
char* buildJSON(BluetoothPacket* devicePacketsRecv, int deviceCount);
void prettyPrintJSON(const char* json);

int main(){
	printf("\nQikBTSniff V0.7 Starting...\n");

	Config config;
	load_config("QikBTSniff.cfg", &config, TRUE);

	//Initial scan just uses one adapter.
	int deviceCount = DeviceFinder(config);
	//"devices" created in BTscan.c
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

	//Need to convert our devices into a struct to save the packet data.
	//I should have thought about the formatting of the MAC earlier to make it more universal across sections, but no big deal to fix it.
	BluetoothPacket devicePacketsRecv[deviceCount];
	memset(devicePacketsRecv, 0, sizeof(devicePacketsRecv));

	for (int i = 0; i < deviceCount; i++)
	{
		//Convert MAC from string "AA:BB:CC:DD:EE:FF" to bytes
		//Remember that we're going to get the MAC reversed.
		sscanf(devices[i].mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &devicePacketsRecv[i].MAC[5], &devicePacketsRecv[i].MAC[4],
			   &devicePacketsRecv[i].MAC[3], &devicePacketsRecv[i].MAC[2],
			   &devicePacketsRecv[i].MAC[1], &devicePacketsRecv[i].MAC[0]);
		strncpy(devicePacketsRecv[i].name, devices[i].name, sizeof(devicePacketsRecv[i].name));
	}

	//get the BT device names first.
	printf("Bluetooth devices:\n");
	for (int i = 0; i < config.HCICount; i++)
	{
		char *name = get_adapter_name(config.HCI[i],FALSE);
		if (name != NULL)
		{
			strncpy(config.BT_names[i], name, 64);
		}
		else
		{
			snprintf(config.BT_names[i], 64, "HCI%d", config.HCI[i]); //fallback
			//printf("Fell back when finding adapter name\n");
		}
		printf("%s\n",config.BT_names[i]);
	}

	DeviceMacsToFind DMTF = build_mac_dev_filters(devices, deviceCount);
	printf("\nLauching ad finder\n");
	//Setup our queue for the scanning threads.
	ThreadSafeQueue <BluetoothPacket> queue;
	//AdFinder(int HCI, DeviceMacsToFind MacsToFind, int Timeout, int intervalms, int debug_lvl, BluetoothPacket) {
	std::vector<std::thread>threads;
	int scantime = 71;
	for (int i = 0; i < config.HCICount; i++) {
		if(scantime > 100) scantime = (scantime - 50);
		int HCIDev = config.HCI[i];//there was an odd threading issue passing this true, so created this.
		threads.emplace_back([&,scantime, HCIDev]() { //[&] — capture everything by reference. Need to ensure some get a hard value
			AdFinder(HCIDev, DMTF, config.bt_restart_timer, scantime, config.verbose, queue);
			});
		scantime += 21;
	}

	unsigned now = (unsigned)time(NULL);
	unsigned TCPSendTime = (unsigned)time(NULL);
	unsigned namesPickedUp = 0;
	int HCI_MSG_RCV[32] = {0};//Just counting who got the most messages.
	while(1){
		unsigned TCPSendTime = now + config.msg_collate_time;
		while (now<TCPSendTime)
		{//This is problamatic, we need messages to come in to update now...
			now = (unsigned)time(NULL);
			if(config.verbose> 2)printf("Will send next TCP packet in %d seconds\n", (TCPSendTime - now));
			BluetoothPacket pkt = queue.pop(); // blocks until data available
			uint16_t uuid = 0;
			int i = 0;
			//I struggled with getting the UUID from packets for way too long.
			//It got really obnoxious with sensors that use FF (manufacturer specific)
			//To make this as versatile as possible, we're going to make a UUID out of the ad type and length
			//Even for FF packets, this gives us a good chance of being able to differentiate the types.
			//Also had issues with even standard packets where the UUID was in odd positions, so this solves multiple issues.
			//The main thing we'll need to skip is the flags.This means byte 1 or 4 will usually be the type.
			uint8_t ad_type = 0;
			while (i < pkt.data_len) {
				uint8_t ad_len  = pkt.data[i];
				ad_type = pkt.data[i + 1];
				if (ad_type != 0x01) { //skip flags, take the first real structure
					uuid = (ad_type << 8) | ad_len;
					break;
				}
				i += ad_len + 1;
			}

			if(ad_type == 0x08 || ad_type == 0x09){
				namesPickedUp++;
				continue;
			}


			if ((uuid == 0)||(uuid == 0))  // not ad type we want.
			{
				if (config.verbose > 1)
				{
					printf("[HCI%d] No UUID found, skipping:", pkt.hciNo);
					for (int i = 0; i < pkt.data_len; i++)
					{
						printf("%02X,", pkt.data[i]);
					}
				
				}
				continue; // back to start of while loop (queue.pop)
			}

			//increment that our adapter got a fresh message.
			HCI_MSG_RCV[pkt.hciNo] += 1;

			// Lets store our data for sending later.
			// First, Find device by MAC
			for (int i = 0; i < deviceCount; i++)
			{
				if (memcmp(pkt.MAC, devicePacketsRecv[i].MAC, 6) == 0)
				{
					// Find existing UUID slot or create new one
					BluetoothPacket &CurrDev = devicePacketsRecv[i];
					UUIDRecord *target = nullptr;
					for (int j = 0; j < CurrDev.uuid_count; j++)
					{
						if (CurrDev.uuids[j].uuid == uuid)
						{
							target = &CurrDev.uuids[j]; // existing UUID, overwrite data for it
							break;
						}
					}
					if (target == nullptr && CurrDev.uuid_count < 16)
					{
						target = &CurrDev.uuids[CurrDev.uuid_count++]; // new UUID slot created
						target->uuid = uuid;
					}
					if (target != nullptr)
					{
						memcpy(target->data, pkt.data, pkt.data_len);//write our data to new or existing slot.
						target->data_len = pkt.data_len;
						target->count += 1;
					}
					break;
				}
			}

			if (config.verbose > 2)
			{ // print packet
				printf("[HCI%d] PKT RECVD: UUID-%02X MAC-%02X:%02X:%02X:%02X:%02X:%02X  len-%d  payload-",
						uuid,
						pkt.hciNo,
						pkt.MAC[0], pkt.MAC[1], pkt.MAC[2], pkt.MAC[3], pkt.MAC[4], pkt.MAC[5],
						pkt.data_len);
				for (int i = 0; i < pkt.data_len; i++)
					printf("%02x ", pkt.data[i]);
				printf("\n");
			}		
			now = (unsigned)time(NULL);
		}

		

		//TCP send time!
		//Build our JSON packet. Need to free the payload after send! Otherwise we'll probably have a memory leak type scenario.
		char* payload = buildJSON(devicePacketsRecv, deviceCount);

		unsigned devicesDetected = deviceCount;
		if (config.verbose > 1)
		{
			prettyPrintJSON(payload);
		}

		char timeStr[20]; // "DD/MM/YYYY HH:MM:SS" + null
		time_t t = time(NULL);
		struct tm *currentTime = localtime(&t);
		snprintf(timeStr, sizeof(timeStr), "%02d/%02d/%04d %02d:%02d:%02d",
			currentTime->tm_mday, currentTime->tm_mon + 1, currentTime->tm_year + 1900,
			currentTime->tm_hour, currentTime->tm_min, currentTime->tm_sec);

				
		//Nextbit is all different debug print stuff.
		if (config.verbose > 0)
		{

			printf(" --------- \nTCP sending at : %s\n",timeStr);
			for (int i = 0; i < deviceCount; i++)
			{
				printf("Dev: %s - ", devicePacketsRecv[i].name);
				if(devicePacketsRecv[i].uuid_count > 0){
				for (int j = 0; j < devicePacketsRecv[i].uuid_count; j++)
				{
					printf(" 0x%04X(%d) ",
						   devicePacketsRecv[i].uuids[j].uuid,
						   devicePacketsRecv[i].uuids[j].count);
				}
			}else{
				printf(" None!");
				devicesDetected--;//Cheap way to see how many devices got no packets.
			}
				printf("\n");
			}
			printf("Messages received per adapter:\n");
			struct hci_dev_info di;
			for (int i = 0; i < 32; i++) {
				if (HCI_MSG_RCV[i] > 0) {
					printf("%s - %d packets\n",config.BT_names[i], HCI_MSG_RCV[i]);
					//delete for the next run
					HCI_MSG_RCV[i] =0;
				}
			}
			// have this in as I found it interesting that sensors can still be sending their name long after the active scan has finished.
			printf("Picked up %d name packets during passive scan.\n --------- \n", namesPickedUp);
		}
		else
		{
			printf("TCP send for %d devices out of %d.", devicesDetected, deviceCount);
			printf("\n");
		}

		//Debug finished.
		//Actually send the packet now.
		if (payload)
		{
			int sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock < 0){
				printf("\n!!!!!!!!!!!!\nTCP failed to create socket! Will try again on next run.\n!!!!!!!!!!!!\n");
				break;
			}

			//get our IP and port from the config.
			char ip[16];
			int port;
			sscanf(config.tcp_add, "%15[^:]:%d", ip, &port);	
			struct sockaddr_in server;
			server.sin_family = AF_INET;
			server.sin_port = htons(port);
			server.sin_addr.s_addr = inet_addr(ip);

			if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0)
			{
				int chk = send(sock, payload, strlen(payload), 0);
				if(chk < 0){
					printf("\n!!!!!!!!!!!!\nTCP send failed for %s! Will try again on next run.\n!!!!!!!!!!!!\n",config.tcp_add);
				}else if(config.verbose >0){
					printf("\nTCP sent successfully to %s at %s!\n",config.tcp_add,timeStr);
				}
			}else{
				printf("\n!!!!!!!!!!!!\nTCP connect failed for %s! Will try again on next run.\n!!!!!!!!!!!!\n",config.tcp_add);
			}

			close(sock);//Do we need to actually close this since we'll use it again?- Yes. Otherwise it will create a new socket each run.
						//Don't want to make the socket a constant in case it fails, probably not an issue creating a new sock everytime?
		}else{
			printf("\n!!!!!!!!!!!!\nNo payload to send!\n!!!!!!!!!!!!\n");
		}

		//Clear out the packets recieved for the next run.
		for (int i = 0; i < deviceCount; i++)
		{
			memset(devicePacketsRecv[i].uuids, 0, sizeof(devicePacketsRecv[i].uuids));
			devicePacketsRecv[i].uuid_count = 0;
		}
		namesPickedUp = 0;
		//free(payload);
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
	printf("HCIdevice(s):");
    for (int i = 0; i < (config->HCICount); i++)
    {
        printf("%d ", config->HCI[i]);
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



char* buildJSON(BluetoothPacket* devicePacketsRecv, int deviceCount) {
    size_t bufSize = 14 + (deviceCount * 1800);
    char* out = (char*)malloc(bufSize);
    if (!out) return NULL;

    int pos = 0;

    pos += snprintf(out + pos, bufSize - pos, "{\"devices\":{");

    for (int i = 0; i < deviceCount; i++) {
        BluetoothPacket& pkt = devicePacketsRecv[i];

        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
            pkt.MAC[5], pkt.MAC[4], pkt.MAC[3],
            pkt.MAC[2], pkt.MAC[1], pkt.MAC[0]);//lets reverse the MAC to normal format (AGAIN!)

        pos += snprintf(out + pos, bufSize - pos, "\"%s\":{\"mac\":\"%s\",\"uuids\":{",
            pkt.name, mac);

        for (int j = 0; j < pkt.uuid_count; j++) {
            UUIDRecord& rec = pkt.uuids[j];

            char dataHex[65] = {0};
            for (int k = 0; k < rec.data_len; k++) {
                snprintf(dataHex + (k * 2), 3, "%02X", rec.data[k]);
            }

            pos += snprintf(out + pos, bufSize - pos, "\"0x%04X\":{\"data\":\"%s\"}",
                rec.uuid, dataHex);

            if (j < pkt.uuid_count - 1) pos += snprintf(out + pos, bufSize - pos, ",");
        }

        pos += snprintf(out + pos, bufSize - pos, "}}");
        if (i < deviceCount - 1) pos += snprintf(out + pos, bufSize - pos, ",");
    }

    pos += snprintf(out + pos, bufSize - pos, "}}");
    return out;
}

void prettyPrintJSON(const char* json) {//Need to see the json in a readable format!
    int indent = 0;
    bool inString = false;
	printf("--------------------------------------\n");
	printf("Pretty JSON of JSON that will be sent!\n");
    for (int i = 0; json[i] != '\0'; i++) {
        char c = json[i];

        // Track whether we're inside a string so we don't format its contents
        if (c == '"' && (i == 0 || json[i-1] != '\\')) inString = !inString;

        if (!inString) {
            if (c == '{' || c == '[') {
                printf("%c\n", c);
                indent++;
                for (int j = 0; j < indent; j++) printf("  ");
            } else if (c == '}' || c == ']') {
                printf("\n");
                indent--;
                for (int j = 0; j < indent; j++) printf("  ");
                printf("%c", c);
            } else if (c == ',') {
                printf(",\n");
                for (int j = 0; j < indent; j++) printf("  ");
            } else if (c == ':') {
                printf(": ");
            } else {
                printf("%c", c);
            }
        } else {
            printf("%c", c);
        }
    }
    printf("\n");
	printf("--------------------------------------\n");
}