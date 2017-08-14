/*
 * QEMU USB HID devices
 *
 * Copyright (c) 2005 Fabrice Bellard
 * Copyright (c) 2007 OpenMoko, Inc.  (andrew@openedhand.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


extern "C"
{

#include "qemu-common.h"
#include "qemu-timer.h"
#include "qdict.h"
#include "qlist.h"
#include "qstring.h"
#include "qobject.h"
#include "qjson.h"

#include "hw/hw.h"
#include "hw/usb.h"
#include "hw/usb/desc.h"
#include "hw/qdev.h"
#include "hw/usb.h"
#include "console.h"
#include <stdio.h>

}

#include <s2e/s2e_qemu.h>
#include <s2e/S2EExecutionState.h>

extern "C" {

#define USB_GENERIC_VERBOSE_LV 0
#define USB_GENERIC_NORMAL 1

#define foreach_desc(max, qlist, function, type, __descs, args)\
	int count = 0;\
	QObject *tmp;\
	type *descs = (type*) calloc(max, sizeof(type)); \
	while(tmp = qlist_pop(qlist), tmp){ \
		assert(count < max); \
		type *tmp_desc = function(tmp, args); \
		fflush(stderr); \
		assert(tmp_desc); \
		descs[count] = *tmp_desc; \
		free(tmp_desc); \
		++count; \
	} \
	assert(count == max);\
	__descs = descs


struct USBDesc *__usb_description;

typedef struct USBGenericState {
	USBDevice dev;
	USBEndpoint *intr;
	int64_t last;	
	int64_t last_tower_version_req;	
	int64_t async_flag;
	int64_t flag;
	int64_t num_requests;

	//Generic JSON descriptor files
	char *iface_desc_fname;
	char *dev_desc_fname;
	char *strings_desc_fname;
	char *id_desc_fname;
	char *desc_dir_fname;

	struct USBDescIface *interface_desc;
	USBDescStrings *strings_desc;
	struct USBDescDevice *device_desc;
	struct USBDescID *id_desc;
	struct USBDesc *usb_description;
} USBGenericState;

enum {
	STR_MANUFACTURER = 1,
	STR_PRODUCT,
	STR_SERIALNUMBER,
	STR_CONFIG,
};

static const USBDescStrings default_desc_strings = {
	[STR_MANUFACTURER]     = "QEMU " QEMU_VERSION,
	[STR_PRODUCT]    = "QEMU Generic USB (USBDT)",
	[STR_SERIALNUMBER]     = "42", /* == remote wakeup works */
	[STR_CONFIG]  = "Generic USB Config",
};

//static USBDescIface default_desc_iface;
//static USBDescDevice default_desc_device;
//static USBDesc default_desc;

static void usb_handle_reset(USBDevice *dev)
{
	//Reset device here
	if(USB_GENERIC_VERBOSE_LV > 3){
		printf("[+] USB :: %s :: Received reset request.\n", __func__);
	}
	if(USB_GENERIC_VERBOSE_LV > 5){
		fflush(stdout);
	}

}

static void dump_packet_info(USBPacket *p)
{
	if(!p){
		printf("[+] USB :: %s :: Invalid Packet.\n", __func__);  //__LINE__
		fflush(stdout);
		return;
	}
	printf("[+] USB :: %s\n", __func__);
	switch(p->state){
		case USB_PACKET_SETUP:
			printf("\tPacket in Setup state\n");
			break;
		case USB_PACKET_COMPLETE:
			printf("\tPacket in Complete state\n");
			break;
		case USB_PACKET_ASYNC:
			printf("\tPacket in Async state\n");
			break;
		default:
			printf("\tPacket in state: %i\n", p->state);
			break;
	}

	printf("\tp->ep->nr = 0x%02X, p->ep->type = 0x%02X, p->ep->pid = 0x%02X.\n", p->ep->nr, p->ep->type, p->ep->pid);
	printf("\tp->result = %i, p->parameter = %016lX.\n", p->result, p->parameter);

	if(p->ep->type == USB_ENDPOINT_XFER_ISOC){
		printf("\tISOCronous transfer type.\n");
	} else if (p->ep->type == USB_ENDPOINT_XFER_INT){
		printf("\tINTerrupt transfer type.\n");
	} else if (p->ep->type == USB_ENDPOINT_XFER_BULK){
		printf("\tBULK transfer type.\n");
	} else if (p->ep->type == USB_ENDPOINT_XFER_CONTROL){
		printf("\tCONTROL transfer type.\n");
	} else if (p->ep->type == USB_ENDPOINT_XFER_INVALID){
		printf("\tINVALID transfer type.\n");
	}else{
		printf("\tUnknown transfer type.\n");
	}

	if(p->pid == USB_TOKEN_IN){
		printf("\tPacket ID IN.\n");
	}else if(p->pid == USB_TOKEN_OUT){
		printf("\tPacket ID OUT.\n");
	}else if(p->pid == USB_TOKEN_SETUP){
		printf("\tPacket ID SETUP.\n");
	}else{
		printf("\tUnknown Packet ID.\n");
	}

	fflush(stdout);
	return;
}

static int inject_fault(USBPacket *p)
{
	int ret = 0;
	if(g_s2e_state->m_USB_FAULT){
		printf("[+] USB :: Injecting USB_RET_NAK to fault state.\n");
		g_s2e_state->m_USB_FAULT = 0;
		ret = USB_RET_NAK;
	}else{
		//randomly inject faults
		if(rand() % 3 == 0){
			printf("[+] USB :: Injecting USB_RET_NAK to fault state.\n");
			ret = USB_RET_NAK;
		}
	}
	return ret;
}



/* Handle USB Control messages */
static int usb_handle_control(USBDevice *dev, USBPacket *p,
		int request, int value, int index, int length, uint8_t *data)
{
	
	if(USB_GENERIC_VERBOSE_LV > 2){
		printf("[+] USB :: /==============================================\\\n");
		printf("[+] USB :: %s :: Received usb control request.\n", __func__);
		printf("[+] USB :: request = %i, value = %i, index = %i, length = %i.\n", request, value, index, length);
	}
	if(USB_GENERIC_VERBOSE_LV > 7){
		fflush(stdout);
		dump_packet_info(p);
	}

	if(USB_GENERIC_VERBOSE_LV > 3){
		if((DeviceRequest & request) == DeviceRequest)
			printf("[+] USB :: Control :: Device IN Request.\n");
		if((InterfaceRequest & request) == InterfaceRequest)
			printf("[+] USB :: Control :: Interface IN Request.\n");
		if((EndpointRequest & request) == EndpointRequest)
			printf("[+] USB :: Control :: Endpoint IN Request.\n");
		if((ClassInterfaceRequest & request) == ClassInterfaceRequest)
			printf("[+] USB :: Control :: ClassInterface IN Request.\n");

		if((DeviceOutRequest & request) == DeviceOutRequest)
			printf("[+] USB :: Control :: Device OUT Request.\n");
		if((InterfaceOutRequest & request) == InterfaceOutRequest)
			printf("[+] USB :: Control :: Interface OUT Request.\n");
		if((EndpointOutRequest & request) == EndpointOutRequest)
			printf("[+] USB :: Control :: Endpoint OUT Request.\n");
		if((ClassInterfaceOutRequest & request) == ClassInterfaceOutRequest)
			printf("[+] USB :: Control :: ClassInterface OUT Request.\n");


		if((USB_TYPE_VENDOR & request) == USB_TYPE_VENDOR){
			printf("[+] USB :: Control :: Type Vendor Request.\n");
		}
	}
	fflush(stdout);

	int ret;
	//check generic control handler
	ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
	if (ret >= 0) {
		if(USB_GENERIC_VERBOSE_LV > 3){
			printf("[+] USB :: Generic USB descriptor control request\n");
			printf("[+] USB :: \\==============================================/\n");
		}
		return ret;
	}

	printf("[+] USB :: Non generic USB descriptor control request\n");
	fflush(stdout);

	ret = inject_fault(p);

#ifdef USB_GENERIC_MAX_REQ
	USBGenericState *ugs = DO_UPCAST(USBGenericState, dev, dev);

	ugs->num_requests += 1;
	if(ugs->num_requests > 50){
		return USB_RET_ASYNC;
	}
#endif


	//Respond differently to custom device requests
	switch(request & 0xFF){
#ifdef USB_GENERIC_LEGOUSBTOWER
		case 0xFD: //TOWER_REQUEST_GET_VERSION
			if(USB_GENERIC_VERBOSE_LV > 3){
				printf("[+] USB :: TOWER_REQUEST_GET_VERSION.\n");
			}
			if(USB_GENERIC_VERBOSE_LV > 5){
				fflush(stdout);
			}

			//ret = USB_RET_STALL;
			if(ugs->async_flag == 0){
				ret = USB_RET_ASYNC;
				ugs->async_flag = 1;
			}else{
				ret = USB_RET_NAK;
			}

			break;

			int64_t now = qemu_get_clock_ns(vm_clock);
			int64_t ms100 = 1000 * 1000 * 100; //100ms

			if(USB_GENERIC_VERBOSE_LV > 5){
				printf("[+] USB :: now() - %zi : last() - %zi\n", now, ugs->last_tower_version_req);
			}

			//first request after success
			if(ugs->last_tower_version_req == 0 || (now - ugs->last_tower_version_req < ms100)){
				ret = USB_RET_STALL;
				//ret = USB_RET_ASYNC;
				ugs->last_tower_version_req = now;
			}else{

				memset(data, 41, length); //A
				//usb_packet_copy(p, buf, length-1);
				ret = length;

				if(USB_GENERIC_VERBOSE_LV > 5){
					printf("[+] USB :: Copied A's.\n");
					fflush(stdout);
				}
			}
			break;
		case 0x04: //LEGO_USB_TOWER_REQUEST_RESET
			if(USB_GENERIC_VERBOSE_LV > 3){
				printf("[+] USB :: TOWER_REQUEST_REQUEST_RESET.\n");
			}
			if(USB_GENERIC_VERBOSE_LV > 5){
				fflush(stdout);
			}

			//memset(data, 41, length); //driver ignore response
			ret = 0;
			break;
#endif
		default:
			if(USB_GENERIC_VERBOSE_LV > 3){
				printf("[+] USB :: Warning - Unkown control request.\n");
			}
			if(USB_GENERIC_VERBOSE_LV > 5){
				fflush(stdout);
			}

			memset(data, 41, length); //Fill desired length with A's and return
			ret = length;

			break;
	}


	if(USB_GENERIC_VERBOSE_LV > 3){
		printf("[+] USB :: \\==============================================/\n");
	}
	return ret;

}

static void dump_hex(uint8_t *data, size_t len)
{
	size_t i;
	for(i=0;i<len;++i){
		printf("0x%02X ", data[i]);
	}
}

static int usb_handle_data(USBDevice *dev, USBPacket *p)
{

#ifdef USB_GENERIC_MAX_REQUESTS
	USBGenericState *ugs = DO_UPCAST(USBGenericState, dev, dev);
	ugs->num_requests += 1;
	if(ugs->num_requests > 50){
		return USB_RET_ASYNC;
	}
#endif

	if(USB_GENERIC_VERBOSE_LV > 3){
		printf("[+] USB :: /==============================================\\\n");
		printf("[+] USB :: Handle Data.\n");
	}
	if(USB_GENERIC_VERBOSE_LV > 7){
		dump_packet_info(p);
		fflush(stdout);
	}

	//handle USB packets
	uint8_t buf[p->iov.size];
	char str_buf[p->iov.size+1];
	int ret = 0;

	switch (p->pid) {
	case USB_TOKEN_IN:
		if(USB_GENERIC_VERBOSE_LV > 3){
			printf("[+] USB :: Received USB Data IN request.\n");
		}
		if (p->ep->nr == 1) {

#ifdef USB_GENERIC_NORMAL
			//No delay, fill and return
			memset(buf, 0, p->iov.size);
			memset(buf, 0x41, p->iov.size); //write A's
			usb_packet_copy(p, buf, p->iov.size);
			ret = p->iov.size;
			ret = inject_fault(p);
			break;
#endif
#ifdef USB_GENERIC_N_DELAY
			if(ugs->flag == 0){
				memset(buf, 0, p->iov.size);
				memcpy(buf, "Hello World!", 12);
				usb_packet_copy(p, buf, p->iov.size);
				ret = p->iov.size;
				ugs->flag = 1;
			}else{
				ret = USB_RET_NAK;
			}
			break;
#endif
#ifdef USB_GENERIC_DELAY
			int64_t now = qemu_get_clock_ns(vm_clock);
			int64_t udelay = 1000 * 1000 * 1; //1 ms

			if(USB_GENERIC_VERBOSE_LV > 5){
				printf("[+] USB :: now() - %zi : last() - %zi\n", now, ugs->last);
			}

			if((now - ugs->last) > udelay){
				if(USB_GENERIC_VERBOSE_LV > 5){
					printf("[+] USB :: p->iov.size:%zi\n", p->iov.size);
				}

				memset(buf, 0, p->iov.size);
				memcpy(buf, "Hello World!", 13);
				usb_packet_copy(p, buf, 13);

				//p->pid = 0x2B; //ACK
				//p->pid = 0xA5; //NACK
				//p->pid = 0x3C; //DATA0

				ret = p->result;

				if(USB_GENERIC_VERBOSE_LV > 5){
					printf("[+] USB :: Data: %s\n", buf);
					printf("[+] USB :: Dumping data as hex: ");
					dump_hex(buf, p->iov.size);
					printf("\n");
					fflush(stdout);
				}
			}else{
				//Set no data NAK
				if(USB_GENERIC_VERBOSE_LV > 3){
					printf("[+] USB :: Delaying URB, returning with NAK\n");
				}
				if(USB_GENERIC_VERBOSE_LV > 5){
					fflush(stdout);
				}

				ret = USB_RET_NAK;
			}
			ugs->last = qemu_get_clock_ns(vm_clock);
			break;
#endif
		} else {
			goto fail;
		}
		break;
	case USB_TOKEN_OUT:
		//copy iovec to buffer
		//qemu_iovec_to_buffer(p->iov, obuf);
		usb_packet_copy(p, buf, p->iov.size);

		if(USB_GENERIC_VERBOSE_LV > 5){
			printf("[+] USB :: Dumping data as hex: ");
			dump_hex(buf, p->iov.size);
			printf("\n");


			//memcpy(str_buf, buf, ret);
			snprintf(str_buf, p->iov.size + 1, "%s\n", buf);
			printf("[+] USB :: p->iov.size:%zi\n", p->iov.size);
			printf("[+] USB :: %s\n", str_buf);
			fflush(stdout);
		}
		ret = p->iov.size;
		break;
	default:
fail:
		ret = USB_RET_STALL;
		break;
	}
	if(USB_GENERIC_VERBOSE_LV > 3){
		printf("[+] USB :: Returning with %i\n", ret);
		printf("[+] USB :: \\==============================================/\n");
	}

	return ret;
}

static void usb_handle_destroy(USBDevice *dev)
{
	printf("[+] USB :: Received destroy request.\n");
	fflush(stdout);

	//USBGenericState *ugs = DO_UPCAST(USBGenericState, dev, dev);

	/* DO NOT FREE STATE STRUCT, QEMU Handles this */
	//free(ugs);
}

static Property usb_host_dev_properties[] = {
	DEFINE_PROP_STRING("iface.json", USBGenericState, iface_desc_fname),
	DEFINE_PROP_STRING("device.json", USBGenericState, dev_desc_fname),
	DEFINE_PROP_STRING("id.json", USBGenericState, id_desc_fname),
	DEFINE_PROP_STRING("strings.json", USBGenericState, strings_desc_fname),
	DEFINE_PROP_STRING("desc-dir", USBGenericState, desc_dir_fname),
	DEFINE_PROP_END_OF_LIST(),
};

static USBDescOther *parse_other_descriptor(QObject *qod)
{
	assert(qod);
	printf("Parsing USBDescOther\n");

	if(qobject_type(qod) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(qod));
		return NULL;
	}

	struct USBDescOther *od = (struct USBDescOther*)malloc(sizeof(struct USBDescOther));
	if(!od){
		perror("Error allocating memory for USBDescOther!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(qod);

	od->length = (uint8_t) qdict_get_try_int(dict, "length", 0);
	//od->data = (uint8_t*) qdict_get_try_str(dict, "data");
	const char *char_data = qdict_get_try_str(dict, "data");
	assert(strlen(char_data)%2==0);
	size_t len = strlen(char_data)/2;
	uint8_t *data = (uint8_t *) calloc(1, len);
	size_t i;
	for(i=0;i<len;++i){
		char t4c[3];
		snprintf((char*)&t4c, 3, "%c%c" ,*(char_data+(2*i)), *(char_data+(2*i)+1));
		long int bin = strtol((char*)&t4c, NULL, 16);
		data[i] = (uint8_t)(bin & 0xff);
	}

	od->data = data;

	return od;
}

static USBDescConfig *parse_config_descriptor(QObject *cd, USBDescIface *desc_iface)
{
	assert(cd);
	assert(desc_iface);
	if(qobject_type(cd) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(cd));
		return NULL;
	}

	struct USBDescConfig *conf = (struct USBDescConfig*)calloc(1, sizeof(struct USBDescConfig));
	if(!conf){
		perror("Error allocating memory for USBDescConfig!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(cd);


	conf->bNumInterfaces = (uint8_t) qdict_get_try_int(dict, "bNumInterfaces", 0);
	conf->bConfigurationValue = (uint8_t) qdict_get_try_int(dict, "bConfigurationValue", 0);
	conf->iConfiguration = (uint8_t) qdict_get_try_int(dict, "iConfiguration", 0);
	conf->bmAttributes = (uint8_t) qdict_get_try_int(dict, "bmAttributes", 0);
	conf->bMaxPower = (uint8_t) qdict_get_try_int(dict, "bMaxPower", 0);
	conf->nif_groups = (uint8_t) qdict_get_try_int(dict, "nif_groups", 0);
	conf->nif = (uint8_t) qdict_get_try_int(dict, "nif", 1);

	conf->ifs = desc_iface;

	/* grouped interfaces */
	/*
	   uint8_t                   nif_groups;
	   const USBDescIfaceAssoc   *if_groups;
	 */

	return conf;
}

/* Pass an array of USBDescConfig's	*/
static USBDescDevice *parse_device_descriptor(QObject *qd, USBDescIface *iface_desc)
{
	assert(qd);
	if(qobject_type(qd) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(qd));
		return NULL;
	}

	struct USBDescDevice *dev = (struct USBDescDevice*)calloc(1, sizeof(struct USBDescDevice));
	if(!dev){
		perror("Error allocating memory for USBDescDevice!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(qd);

	dev->bcdUSB = (uint16_t) qdict_get_try_int(dict, "bcdUSB", 0);
	dev->bDeviceClass = (uint8_t) qdict_get_try_int(dict, "bDeviceClass", 0);
	dev->bDeviceSubClass = (uint8_t) qdict_get_try_int(dict, "bDeviceSubClass", 0);
	dev->bDeviceProtocol = (uint8_t) qdict_get_try_int(dict, "bDeviceProtocol", 0);
	dev->bMaxPacketSize0 = (uint8_t) qdict_get_try_int(dict, "bMaxPacketSize0", 0);
	dev->bNumConfigurations = (uint8_t) qdict_get_try_int(dict, "bNumConfigurations", 1);

	assert(dev->bNumConfigurations > 0);

	QObject *confs = qdict_get(dict, "confs");
	if(!confs){
		fprintf(stderr, "Error parsing Interface descriptor. Invalid Spec. No USBDescEndpoint.\n");
		return NULL;
	}
	assert(qobject_type(confs) == QTYPE_QLIST);
	QList *conf_list = qobject_to_qlist(confs);

	USBDescConfig *configs = NULL;
	foreach_desc(dev->bNumConfigurations, conf_list, parse_config_descriptor, USBDescConfig, configs, iface_desc);
	assert(configs);
	dev->confs = configs;

	return dev;
}



static USBDescID *parse_usbid_descriptor(QObject *usbid)
{
	assert(usbid);
	if(qobject_type(usbid) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(usbid));
		return NULL;
	}

	struct USBDescID *descid = (struct USBDescID*)malloc(sizeof(struct USBDescID));
	if(!descid){
		perror("Error allocating memory for USBDescID!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(usbid);

	descid->idVendor = (uint16_t) qdict_get_try_int(dict, "idVendor", 0);
	descid->idProduct = (uint16_t) qdict_get_try_int(dict, "idProduct", 0);
	descid->bcdDevice = (uint16_t) qdict_get_try_int(dict, "bcdDevice", 0);
	descid->iManufacturer = (uint8_t) qdict_get_try_int(dict, "iManufacturer", 0);
	descid->iProduct = (uint8_t) qdict_get_try_int(dict, "iProduct", 0);
	descid->iSerialNumber = (uint8_t) qdict_get_try_int(dict, "iSerialNumber", 0);

	printf("Parsed USB ID\nidVendor: %i\tidProduct: %i\n", descid->idVendor, descid->idProduct);
	return descid;
}


static USBDescStrings *parse_strings_descriptor(QObject *strd)
{
	assert(strd);
	if(qobject_type(strd) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(strd));
		return NULL;
	}

	USBDescStrings *stringsd = (USBDescStrings*)calloc(1, sizeof(USBDescStrings));
	if(!stringsd){
		perror("Error allocating memory for USBDescStrings!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(strd);
	const char *manufacturer =  qdict_get_try_str(dict, "STR_MANUFACTURER");
	const char *product =  qdict_get_try_str(dict, "STR_PRODUCT");
	const char *serial =  qdict_get_try_str(dict, "STR_SERIALNUMBER");
	const char *config =  qdict_get_try_str(dict, "STR_CONFIG");

	(*stringsd)[STR_MANUFACTURER] = manufacturer;
	(*stringsd)[STR_PRODUCT] = product;
	(*stringsd)[STR_SERIALNUMBER] = serial;
	(*stringsd)[STR_CONFIG] = config;

	return stringsd;
};

/*
 *	Generate USB Decriptor 
 */
static USBDesc *gen_usb_descriptor(USBDescID usbid, USBDescDevice *full, USBDescDevice *high, const USBDescStrings *usbstrings)
{
	assert(usbstrings);
	assert(full || high);

	struct USBDesc *usb_desc = (struct USBDesc*)calloc(1, sizeof(struct USBDesc));
	if(!usb_desc){
		perror("Error allocating memory for USBDesc!\n");
		return NULL;
	}

	usb_desc->str = (const char *const *)usbstrings;
	usb_desc->id = usbid;
	usb_desc->full = full;
	usb_desc->high = high;

	return usb_desc;
}




static USBDescEndpoint *parse_endpoint_descriptor(QObject *qep)
{
	assert(qep);

	if(qobject_type(qep) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(qep));
		return NULL;
	}

	struct USBDescEndpoint *ep = (struct USBDescEndpoint*)calloc(1, sizeof(struct USBDescEndpoint));
	if(!ep){
		perror("Error allocating memory for USBDescEndpoint!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(qep);

	ep->bEndpointAddress = (uint8_t) qdict_get_try_int(dict, "bEndpointAddress", 0x81);
	ep->bmAttributes = (uint8_t) qdict_get_try_int(dict, "bmAttributes", USB_ENDPOINT_XFER_INT);
	ep->wMaxPacketSize = (uint16_t) qdict_get_try_int(dict, "wMaxPacketSize", 64);
	ep->bInterval = (uint8_t) qdict_get_try_int(dict, "bIntervales", 0x0a);
	ep->bRefresh = (uint8_t) qdict_get_try_int(dict, "bRefreshes", 0);
	ep->bSynchAddress = (uint8_t) qdict_get_try_int(dict, "bSynchAddress", 0);
	ep->is_audio = (uint8_t) qdict_get_try_int(dict, "is_audio", 0);

	return ep;
}

static QObject *json_file_to_qobj(char *fname)
{
	int ret = 0;
	long len = 0;
	FILE *f = fopen(fname, "r");
	if(!f){
		fprintf(stdout, "Failed to open file: %s\n", fname);
		return NULL;
	}
	//get length of file
	ret = fseek(f, 0L, SEEK_END);
	if(ret == -1){
		fprintf(stdout,"Error seeking to file position!\n");
		return NULL;
	}

	len = ftell(f);

	ret = fseek(f, 0L, SEEK_SET);
	if(ret != 0){
		fprintf(stdout,"Error resetting file position!\n");
		return NULL;
	}

	char *buf = (char*) calloc(1, len+1);
	if(!buf){
		fprintf(stdout,"Error allocating memory for file buffer!\n");
		return NULL;
	}
	ret = fread(buf, len, 1, f);
	if(ret != 1){
		fprintf(stdout, "Error reading from file: %s!\n", fname);
		return NULL;
	}
	fclose(f);
	buf[len] = '\0';

	printf("USB :: Converting to json \t-\n\t\t\t\t `\n\t\t\t\t  |\n");
	printf("JSON::%s", buf);
	fflush(stdout);

#pragma GCC diagnostic ignored "-Wformat"
	QObject *data = qobject_from_json(buf);
#pragma GCC diagnostic warning "-Wformat"

	return data;
}

static USBDescIface *parse_iface_descriptor(QObject *iface_desc)
{
	fflush(stderr);
	fflush(stdout);
	assert(iface_desc);


	if(qobject_type(iface_desc) == QTYPE_QSTRING){
		printf("iface_desc qobject: %s\n", qstring_get_str( qobject_to_qstring(iface_desc) ));
	}

	if(qobject_type(iface_desc) != QTYPE_QDICT){
		fprintf(stderr, "Error, base object not of type dictionary but of %i\n", qobject_type(iface_desc));
		return NULL;
	}

	struct USBDescIface *ifd = (struct USBDescIface*)calloc(1, sizeof(struct USBDescIface));
	if(!ifd){
		perror("Error allocating memory for USBDescIface!\n");
		return NULL;
	}

	QDict *dict = qobject_to_qdict(iface_desc);

	ifd->bInterfaceNumber = (uint8_t) qdict_get_try_int(dict, "bInterfaceNumber", 0);
	ifd->bAlternateSetting = (uint8_t) qdict_get_try_int(dict, "bAlternateSetting", 0);
	ifd->bNumEndpoints = (uint8_t) qdict_get_try_int(dict, "bNumEndpoints", 0);
	ifd->bInterfaceClass = (uint8_t) qdict_get_try_int(dict, "bInterfaceClass", 0);
	ifd->bInterfaceSubClass = (uint8_t) qdict_get_try_int(dict, "bInterfaceSubClass", 0);
	ifd->bInterfaceProtocol = (uint8_t) qdict_get_try_int(dict, "bInterfaceProtocol", 0);
	ifd->iInterface = (uint8_t) qdict_get_try_int(dict, "iInterface", 0);
	ifd->ndesc = (uint8_t) qdict_get_try_int(dict, "ndesc", 0);

	QObject *tmp;

	if(ifd->ndesc >= 1){
		QObject *descs = qdict_get(dict, "descs");
		if(!descs){
			fprintf(stderr, "Error parsing Interface descriptor. Invalid Spec. No USBDescOther.\n");
			return NULL;
		}
		assert(qobject_type(descs) == QTYPE_QLIST);
		QList *desc_list = qobject_to_qlist(descs);

		//Parse USBDescOther's
		int desc_count = 0;
		struct USBDescOther *usb_descs = (struct USBDescOther*) calloc(ifd->ndesc, sizeof(struct USBDescOther));
		while(tmp = qlist_pop(desc_list), tmp){
			assert(desc_count < ifd->ndesc);
			USBDescOther *tmp_desc = parse_other_descriptor(tmp);
			fflush(stderr);
			assert(tmp_desc);
			usb_descs[desc_count] = *tmp_desc;
			free(tmp_desc);
			++desc_count;
		}
		assert(desc_count == ifd->ndesc);
		ifd->descs = usb_descs;
	}

	if(ifd->bNumEndpoints >= 1){

		QObject *eps = qdict_get(dict, "eps");
		if(!eps){
			fprintf(stderr, "Error parsing Interface descriptor. Invalid Spec. No USBDescEndpoint.\n");
			return NULL;
		}
		assert(qobject_type(eps) == QTYPE_QLIST);
		QList *eps_list = qobject_to_qlist(eps);


		//Parse USBDescEndpoints's
		struct USBDescEndpoint *usb_eps = (struct USBDescEndpoint*) calloc(ifd->bNumEndpoints, sizeof(struct USBDescEndpoint));
		int ep_count = 0;
		while(tmp = qlist_pop(eps_list), tmp){
			assert(ep_count < ifd->bNumEndpoints);
			USBDescEndpoint *tmp_ep = parse_endpoint_descriptor(tmp);
			fflush(stderr);
			assert(tmp_ep);
			usb_eps[ep_count] = *tmp_ep;
			free(tmp_ep);
			++ep_count;
		}
		//printf("ep_count: %i\nnumendpoints: %i\n", ep_count, ifd->bNumEndpoints);
		assert(ep_count == ifd->bNumEndpoints);
		ifd->eps = usb_eps;
	}

	return ifd;
}

static int parse_usb_generic_descriptors(USBGenericState *ugs)
{
	int ret = 0;

	//find default descriptors
	if(ugs->desc_dir_fname){
		if(!ugs->strings_desc_fname){
			ugs->strings_desc_fname = (char *)malloc(256);
			sprintf(ugs->strings_desc_fname, "%s/%s", ugs->desc_dir_fname, "strings.json");
		}
		if(!ugs->id_desc_fname){
			ugs->id_desc_fname = (char *)malloc(256);
			sprintf(ugs->id_desc_fname, "%s/%s", ugs->desc_dir_fname, "id.json");
		}
		if(!ugs->iface_desc_fname){
			ugs->iface_desc_fname = (char *)malloc(256);
			sprintf(ugs->iface_desc_fname, "%s/%s", ugs->desc_dir_fname, "iface.json");
		}
		if(!ugs->dev_desc_fname){
			ugs->dev_desc_fname = (char *)malloc(256);
			sprintf(ugs->dev_desc_fname, "%s/%s", ugs->desc_dir_fname, "device.json");
		}
	}



	if(ugs->strings_desc_fname){
		QObject *qstrings_desc = json_file_to_qobj(ugs->strings_desc_fname);
		assert(qstrings_desc);
		ugs->strings_desc = parse_strings_descriptor(qstrings_desc);
		assert(ugs->strings_desc);
	}

	if(ugs->id_desc_fname){
		QObject *id_desc = json_file_to_qobj(ugs->id_desc_fname);
		assert(id_desc);
		ugs->id_desc = parse_usbid_descriptor(id_desc);
		assert(ugs->id_desc);
	}

	if(ugs->iface_desc_fname){
		QObject *qiface_desc = json_file_to_qobj(ugs->iface_desc_fname);
		assert(qiface_desc);
		ugs->interface_desc = parse_iface_descriptor(qiface_desc);
		assert(ugs->interface_desc);
	}
	if(ugs->dev_desc_fname){
		QObject *qdev_desc = json_file_to_qobj(ugs->dev_desc_fname);
		assert(qdev_desc);
		ugs->device_desc = parse_device_descriptor(qdev_desc, ugs->interface_desc);
		assert(ugs->device_desc);
	}

	ugs->usb_description = gen_usb_descriptor(*(ugs->id_desc), ugs->device_desc, NULL, ugs->strings_desc);
	assert(ugs->usb_description);

	printf("Parsed USB Descriptors!\n");
	fflush(stdout); fflush(stderr);

	return ret;
}

static int init_usb_generic(USBGenericState *ugs)
{
	assert(ugs); //critcal error if null
	printf("[+] USB :: Initialising USB Generic descriptors.\n");

	printf("[+] USB :: Descriptor files:\n\tiface.json: %s\n\tdevice.json: %s\n\tid.json: %s\n\tstrings.json: %s\n", ugs->iface_desc_fname, ugs->dev_desc_fname, ugs->id_desc_fname, ugs->strings_desc_fname);
	fflush(stdout);

	int ret = 0;
	//ret = parse_usb_generic_descriptors(ugs);

	//ugs->last = qemu_get_clock_ns(vm_clock);
	ugs->last = 0;
	ugs->last_tower_version_req = 0;
	ugs->flag = 0;
	ugs->async_flag = 0;
	ugs->num_requests = 0;
	return ret;
}



static int usb_generic_initfn(USBDevice *dev)
{
	int ret = 0;
	printf("[+] USB :: Initialising generic usb.\n");
	fflush(stdout);

	usb_desc_init(dev);
	USBGenericState *ugs = DO_UPCAST(USBGenericState, dev, dev);

	//us->intr = usb_ep_get(dev, USB_TOKEN_IN, 1);
	assert(ugs);
	ret = init_usb_generic(ugs);


	printf("[+] USB :: Initialised generic usb.\n");
	fflush(stdout);
	return ret;
}

static const VMStateDescription vmstate_usb_generic = {
	.name = "usb-generic",
	.unmigratable = 1,
};


static void usb_generic_class_initfn(ObjectClass *klass, void *data)
{
	printf("[+] USB :: Initialising class interface.\n");
	fflush(stdout);

	//Ad hok hack, fix usb device descriptors to usb-generic/*
	struct USBGenericState *ugs = (struct USBGenericState *)calloc(1, sizeof(struct USBGenericState));
	ugs->desc_dir_fname = (char *)"usb-generic";
	parse_usb_generic_descriptors(ugs);
	__usb_description = ugs->usb_description;
	assert(ugs);
	free(ugs);
	assert(__usb_description);
	assert(__usb_description->full);
	assert(__usb_description->str);


	DeviceClass *dc = DEVICE_CLASS(klass);
	USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

	uc->init           = usb_generic_initfn;
	uc->product_desc   = "QEMU Generic USB";
	//uc->usb_desc       = &desc;
	uc->usb_desc       = __usb_description;

	dc->vmsd = &vmstate_usb_generic;
	dc->props = usb_host_dev_properties;

	uc->handle_reset   = usb_handle_reset;
	uc->handle_control = usb_handle_control;
	uc->handle_data    = usb_handle_data;
	uc->handle_destroy = usb_handle_destroy;

	printf("[+] USB :: Initialised class interface.\n");
	fflush(stdout);
}

static TypeInfo usb_info = {
	.name          = "usb-generic",
	.parent        = TYPE_USB_DEVICE,
	.instance_size = sizeof(USBGenericState),
	.class_init    = usb_generic_class_initfn,
};

static void usb_register_types(void)
{
	printf("[+] USB :: Registering generic usb.\n");
	fflush(stdout);

	type_register_static(&usb_info);
	//usb_legacy_register("usb-generic", "generic", NULL);

	printf("[+] USB :: Registered generic usb.\n");
	fflush(stdout);
}

type_init(usb_register_types)
}
