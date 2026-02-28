#include "BTScan.h"

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

DeviceInfo devices[1000];
//Used for our device list generation.
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

//function I got from Claude to turn our mac string into byte arrays that can be searched with memmem
//Purpose of this is to kick out faster if the mac doesn't even appear in the buffer.
MacFilter prepare_mac_manu_filters(Config* cfg) {
	MacFilter result = { 0 };
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

//This is the full device macs we want to find in LSB for searching through the HCI packet in passive scan mode.
DeviceMacsToFind build_mac_dev_filters(DeviceInfo* devices, int device_count)
{
	DeviceMacsToFind result;
	result.count = 0;

	for (int i = 0; i < device_count && result.count < 100; i++)
	{
		unsigned int b0, b1, b2, b3, b4, b5;

		if (sscanf(devices[i].mac, "%x:%x:%x:%x:%x:%x",
			&b0, &b1, &b2, &b3, &b4, &b5) != 6)
		{
			printf("Malformed MAC in filter!!\n");
			continue;  // skip malformed MAC
		}

		// last 3 bytes of MAC, reversed for wire order
		result.bytes[result.count][0] = (uint8_t)b5;
		result.bytes[result.count][1] = (uint8_t)b4;
		result.bytes[result.count][2] = (uint8_t)b3;
		result.bytes[result.count][3] = (uint8_t)b2;
		result.bytes[result.count][4] = (uint8_t)b1;
		result.bytes[result.count][5] = (uint8_t)b0;

		result.count++;
	}

	return result;
}

int bt_start_scan(int device, int* status, int enable, int interval, int ScanType) {


	le_set_scan_enable_cp scan_cp;

	if (enable) {
		// Scan parameters
		le_set_scan_parameters_cp scan_params_cp;
		memset(&scan_params_cp, 0, sizeof(scan_params_cp));
		scan_params_cp.type = ScanType;
		scan_params_cp.interval = htobs(interval);
		scan_params_cp.window = htobs(interval);
		scan_params_cp.own_bdaddr_type = 0x00;
		scan_params_cp.filter = 0x00;

		struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, status, &scan_params_cp);
		if (hci_send_req(device, &scan_params_rq, 1000) < 0) {
			perror("Failed to set scan parameters");
			return -1;
		}

		// Event mask
		le_set_event_mask_cp event_mask_cp;
		memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
		for (int i = 0; i < 8; i++) event_mask_cp.mask[i] = 0xFF;
		struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, status, &event_mask_cp);
		if (hci_send_req(device, &set_mask_rq, 1000) < 0) {
			perror("Failed to set event mask");
			return -1;
		}

		// Enable scanning
		le_set_scan_enable_cp scan_cp;
		memset(&scan_cp, 0, sizeof(scan_cp));
		scan_cp.enable = 0x01; // Enable flag.
		scan_cp.filter_dup = 0x00;// Filtering disabled.
		//It seems like we'd want filtering of duplicates enabled for this scan, but even the BlueZ devs have mentioned it causing "weirdness"
		//I have tested it and at first glance, it appears to work fine, but then certain devices just won't show up.
		//I've also had a device respond to requests fine, but completely stop actually giving out any messages.
		//Our current filtering is so fast that it's not a concern anyway.
		struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, status, &scan_cp);
		if (hci_send_req(device, &enable_adv_rq, 1000) < 0) {
			perror("Failed to enable scan");
			return -1;
		}
	}
	else
	{
		// Disable scanning.
		memset(&scan_cp, 0, sizeof(scan_cp));
		struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
		int ret = hci_send_req(device, &disable_adv_rq, 1000);
		if (ret < 0) {
			hci_close_dev(device);
			perror("Failed to disable scan.");
			return -1;
		}

	}
	return 0;
}

int AdFinder(int HCI, DeviceMacsToFind MacsToFind, int Timeout, int intervalms, int debug_lvl) {

	int ret, status;
	unsigned now = (unsigned)time(NULL);
	unsigned StartTime = (unsigned)time(NULL);

	int device = hci_open_dev(HCI);
	char resetString[25];

	sprintf(resetString, "hciconfig hci%d reset", HCI);
	//printf("%s\n", resetString);
	//There's odd things that can happen where the adapter gets stuck. A reset can help.
	if (system(resetString) != 0) {
		printf("Device Reset failed\n");
	}

	ret = bt_start_scan(device, &status, TRUE, (intervalms / 0.625), 0x00);
	if (ret < 0) {
		if (errno == EACCES || errno == EPERM) {
			fprintf(stderr, "HCI Permission denied. Try running as root.\n");
		}
		else
		{
			perror("Failed to set scan parameters data");
		}
		return -1;
	}

	if (debug_lvl) {
		printf("Using bluetooth device %d, and resetting every %d seconds.", device, Timeout);
		printf("\n");
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
	int MsgCount = 0;


	//Testing out a first byte bucket to see if we get a speed boost.
	uint64_t buckets[256] = { 0 };  //supports up to 64 MACs
	for (int i = 0; i < MacsToFind.count; i++)
		buckets[MacsToFind.bytes[i][0]] |= (1ULL << i);


	while (MsgCount < 1000)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(device, &readfds);
		struct timeval tv = { 0, 100000 };  // must be reset each iteration
		if (select(device + 1, &readfds, NULL, NULL, &tv) > 0) {
			len = read(device, buf, sizeof(buf));
		}
		else {
			now = (unsigned)time(NULL);
			continue;
		}


		if (len >= 14)
		{
			/* Before trying first byte bucket
			for (int i = 0; i < MacsToFind.count; i++)
			{
				uint8_t* match = memmem(buf, len, MacsToFind.bytes[i], 6);
				*/
			for (int pos = 0; pos < len - 5; pos++)
			{
				uint64_t candidates = buckets[buf[pos]];
				while (candidates)
				{
					int i = __builtin_ctzll(candidates);  // index of lowest set bit
					candidates &= candidates - 1;          // clear lowest set bit

					if (memcmp(&buf[pos], MacsToFind.bytes[i], 6) == 0)
					{
						uint8_t* match = &buf[pos];
						//printf("match! %d\n", MsgCount);
						MsgCount++;
						//data length byte immediately follows the 6 byte MAC
						uint8_t* data_len_ptr = match + 6;

						if (data_len_ptr < buf + len)//In case of corrupt buffer. NB: memory pointers!! so checking that the ptr isn't telling us to go beyond the data we have.
						{
							uint8_t data_len = *data_len_ptr;
							if (data_len_ptr + 1 + data_len <= buf + len)
								//previous check seems pointless with this here, but we need to do previous check first to ensure data_len_ptr isn't rubbish, as this could then make us think this is valid...
							{
								uint8_t* payload = data_len_ptr + 1;
								//payload is now pointing at data_len bytes of advertising data
								//Can pass back to our coallating thread now.
								//if (debug_lvl > 2) {

								//	printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
								//		MacsToFind.bytes[i][0],
								//		MacsToFind.bytes[i][1],
								//		MacsToFind.bytes[i][2],
								//		MacsToFind.bytes[i][3],
								//		MacsToFind.bytes[i][4],
								//		MacsToFind.bytes[i][5]);

								//	printf("Payload (%d bytes from %d bytes): ", data_len, len);
								//	for (int i = 0; i < data_len; i++)
								//	{
								//		printf("%02X,", payload[i]);
								//	}
									printf("\nMsg:%d\n", MsgCount);
								//}
							}
						}
					
					}
				}
			}
		}
	}
		// Disable scanning.
		ret = bt_start_scan(device, &status, FALSE, 0, 0);
		if (ret < 0) {
			hci_close_dev(device);
			perror("Failed to disable scan.");
			return -1;
		}
		else {
			printf("Closed scan!\n");
		}

		hci_close_dev(device);

		return 1;
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
	//printf("%s\n", resetString);
	//There's odd things that can happen where the adapter gets stuck. A reset can help.
	if (system(resetString) != 0) {
		printf("Device Reset failed\n");
	}

	ret = bt_start_scan(device, &status, TRUE, 0x78, 0x01);
	if (ret < 0) {
		if (errno == EACCES || errno == EPERM) {
			fprintf(stderr, "HCI Permission denied. Try running as root.\n");
		}
		else
		{
			perror("Failed to set scan parameters data");
		}
		return -1;
	}

	printf("Using bluetooth device %d and will scan for up to %d seconds or %d devices are found.", device, cfg.initial_scan_time, cfg.max_devices);
	printf("\n");

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
		mac_filter = prepare_mac_manu_filters(&cfg);

	while ((now < EndTime) && (deviceCount < cfg.max_devices))
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(device, &readfds);
		struct timeval tv = { 0, 100000 };  // must be reset each iteration
		if (select(device + 1, &readfds, NULL, NULL, &tv) > 0) {
			len = read(device, buf, sizeof(buf));
		}
		else {
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

			meta_event = (evt_le_meta_event*)(buf + HCI_EVENT_HDR_SIZE + 1);
			if (meta_event->subevent == EVT_LE_ADVERTISING_REPORT)
			{
				uint8_t reports_count = meta_event->data[0];
				void* offset = meta_event->data + 1;
				int done = FALSE;
				// int filtered = FALSE;
				// while (reports_count-- && !known && !filtered)
				while (reports_count-- && !done)
				{
					info = (le_advertising_info*)offset;
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
							char name[32] = { 0 };
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


	if (cfg.verbose) {
		unsigned TotalTime = ((unsigned)time(NULL) - StartTime);
		unsigned MsgsPerSec = msgCount / TotalTime;
		printf("Time taken: %d seconds. \n", TotalTime);
		printf("Messages per second: %d \n", MsgsPerSec);
		printf("Filtered by quick MAC filter: %d \n", quickMacFiltered);
		printf("Hit second filter: %d \n", debugSecondFilterTest);
	}
	printf("Devices found: %d \n", deviceCount);

	// Disable scanning.
	ret = bt_start_scan(device, &status, FALSE, 0 ,0);
	if (ret < 0) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		return -1;
	}

	hci_close_dev(device);

	return deviceCount;
}


