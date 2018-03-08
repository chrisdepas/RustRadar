#include "stdafx.h"
#include "GameNetwork.h"

/* Packet handler forward declaration */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* Entry point */
int _tmain(int argc, _TCHAR* argv[])
{
	puts("Rust Navigator v1.0");
	puts("by Chris Depas");

	pcap_if_t *alldevs; /* Linked List of all devices */
	pcap_if_t *d; /* Selected device */
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print device select prompt */
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description) {
			printf(" (%s)\n", d->description);
        } else {
			printf(" (No description available)\n");
        }
	}

    /* Case: No network devices / missing driver */
	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture.
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		/* Case: Failed to open device, free the device list */
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

    /* Free resources & start capture loop */
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);

	return 0;
}


#define ETHERNET_HEADER_SIZE 14
#define SIZE_UDP 8
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header *ih;
	u_int ip_len;

	ih = (ip_header *)(pkt_data + 14);
	ip_len = (ih->ver_ihl & 0xf) * 4; // Length of IP header

	char* data = (char*)(pkt_data + ETHERNET_HEADER_SIZE + SIZE_UDP + ip_len);
	char* data_end = (char*)pkt_data + header->len;
	int datalen = data_end - data;

	CPacket* packet = (CPacket*)data;
	switch (packet->GetType()) {
		case ConsoleCommand:
			{
				//	break;
				if (datalen <= 30)
					return;
				char chat[256];
				memset(chat, 0, 256);
				int concmdlen = *(int*)(data + 28);
				if (concmdlen < 0 || concmdlen > 1000)
					return;
				printf("[CONSOLE CMD (Length %i)] ", *(int*)(data + 28));
				memcpy(chat, data + 0x20, *(int*)(data + 28));
				printf(chat);
				printf("\n");
				break;
			}
		case EntityPosition:
    		{
        		CEntityPositionPacket* entpos = (CEntityPositionPacket*)packet;
        		printf("[ENTPOS] ID %i moved to (%f, %f, %f), Rotation (%f, %f, %f)", entpos->entityID, entpos->position.x, entpos->position.y, entpos->position.z, entpos->rotation.x, entpos->rotation.y, entpos->rotation.z);
                break;
    		}
		case Tick:
    		{
    			// Local position and angle
    			CTickPacket* entpos = (CTickPacket*)packet;
    			entpos->DecodeInput();
    			break;
    		}

		case Invalid:
		default:
			break;
	}
}