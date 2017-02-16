/*
 * ccnpingserver responds to ping Interests with empty Data.
 * Copyright (C) 2011 University of Arizona
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Author: Cheng Yi <yic@email.arizona.edu>
 */

/* ccnpingserver was extend to build ccnagent (CCN Agent).
 * CCN Agent responds to Interests with ccnMib objects mapping content Data.
 * Copyright (C) 2016 University of Campinas
 *
 * CCN Agent is composed by ccnSystem and ccndStatus objects from ccnMib.
 * Author CCN Agent: Marciel de Lima Oliveira <marciel.oliveira@gmail.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>

#define MAX(a,b) (((a)>(b))?(a):(b))

struct ccn_ping_server {
    struct ccn_charbuf *prefix;
    int count;
    int expire;
};

// parent objects of ccnSystem and ccndStatus
enum ccn_mib_parent_objects {
	CCN_PARENT_OBJECT_SYSTEM = 0,
	CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS,
	CCN_PARENT_OBJECT_STATUS_INTERESTS,
	CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS,
	CCN_PARENT_OBJECT_STATUS_FACES,
	CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES,
	CCN_PARENT_OBJECT_STATUS_FORWARDING,
	CCN_MAX_PARENT_OBJECTS
};

enum ccn_mib_system_objects {
	CCN_SYSTEM_OBJECT_NAME = 0,
	CCN_SYSTEM_OBJECT_UPTIME,
	CCN_SYSTEM_OBJECT_LOADS,
	CCN_SYSTEM_OBJECT_TOTALRAM,
	CCN_SYSTEM_OBJECT_FREERAM,
	CCN_SYSTEM_OBJECT_SHAREDRAM,
	CCN_SYSTEM_OBJECT_BUFFERRAM,
	CCN_SYSTEM_OBJECT_TOTALSWAP,
	CCN_SYSTEM_OBJECT_FREESWAP,
	CCN_SYSTEM_OBJECT_PROCS,
	CCN_SYSTEM_OBJECT_TOTALHIGH,
	CCN_SYSTEM_OBJECT_FREELHIGH,
	CCN_SYSTEM_OBJECT_MEMUNIT,
	CCN_SYSTEM_OBJECT_CHARF,
	CCN_SYSTEM_MAX_OBJECTS
};

// objects of ccndStatus
enum ccn_mib_status_content_items_objects {
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CIACCESSIONED = 0,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CIDUPLICATE,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CISENT,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CISPARSE,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTALE,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTORED,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CIHOST,
	CCN_STATUS_CONTENT_ITEMS_OBJECT_CITIMESTAMP,
	CCN_STATUS_CONTENT_ITEMS_MAX_OBJECTS
};

enum ccn_mib_status_interests_objects {
	CCN_STATUS_INTERESTS_OBJECT_INAMES = 0,
	CCN_STATUS_INTERESTS_OBJECT_INOTED,
	CCN_STATUS_INTERESTS_OBJECT_IPENDING,
	CCN_STATUS_INTERESTS_OBJECT_IPROPAGATING,
	CCN_STATUS_INTERESTS_OBJECT_IHOST,
	CCN_STATUS_INTERESTS_OBJECT_ITIMESTAMP,
	CCN_STATUS_INTERESTS_MAX_OBJECTS
};

enum ccn_mib_status_interest_totals_objects {
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITACCEPTED = 0,
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITDROPPED,
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSENT,
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSTUFFED,
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITHOST,
	CCN_STATUS_INTEREST_TOTALS_OBJECT_ITTIMESTAMP,
	CCN_STATUS_INTEREST_TOTALS_MAX_OBJECTS
};

enum ccn_mib_status_faces_objects {
	CCN_STATUS_FACES_OBJECT_FFACE0 = 0,
	CCN_STATUS_FACES_OBJECT_FFACE1,
	CCN_STATUS_FACES_OBJECT_FFACE2,
	CCN_STATUS_FACES_OBJECT_FFACE3,
	CCN_STATUS_FACES_OBJECT_FFACE4,
	CCN_STATUS_FACES_OBJECT_FFACE5,
	CCN_STATUS_FACES_OBJECT_FFACE6,
	CCN_STATUS_FACES_OBJECT_FFACE7,
	CCN_STATUS_FACES_OBJECT_FFACE8,
	CCN_STATUS_FACES_OBJECT_FFACE9,
	CCN_STATUS_FACES_OBJECT_FFACE10,
	CCN_STATUS_FACES_OBJECT_FFACE11,
	CCN_STATUS_FACES_OBJECT_FFACE12,
	CCN_STATUS_FACES_OBJECT_FFACE13,
	CCN_STATUS_FACES_OBJECT_FFLAGS0,
	CCN_STATUS_FACES_OBJECT_FFLAGS1,
	CCN_STATUS_FACES_OBJECT_FFLAGS2,
	CCN_STATUS_FACES_OBJECT_FFLAGS3,
	CCN_STATUS_FACES_OBJECT_FFLAGS4,
	CCN_STATUS_FACES_OBJECT_FFLAGS5,
	CCN_STATUS_FACES_OBJECT_FFLAGS6,
	CCN_STATUS_FACES_OBJECT_FFLAGS7,
	CCN_STATUS_FACES_OBJECT_FFLAGS8,
	CCN_STATUS_FACES_OBJECT_FFLAGS9,
	CCN_STATUS_FACES_OBJECT_FFLAGS10,
	CCN_STATUS_FACES_OBJECT_FFLAGS11,
	CCN_STATUS_FACES_OBJECT_FFLAGS12,
	CCN_STATUS_FACES_OBJECT_FFLAGS13,
	CCN_STATUS_FACES_OBJECT_FLOCAL0,
	CCN_STATUS_FACES_OBJECT_FLOCAL1,
	CCN_STATUS_FACES_OBJECT_FLOCAL2,
	CCN_STATUS_FACES_OBJECT_FLOCAL3,
	CCN_STATUS_FACES_OBJECT_FLOCAL4,
	CCN_STATUS_FACES_OBJECT_FLOCAL5,
	CCN_STATUS_FACES_OBJECT_FLOCAL6,
	CCN_STATUS_FACES_OBJECT_FLOCAL7,
	CCN_STATUS_FACES_OBJECT_FLOCAL8,
	CCN_STATUS_FACES_OBJECT_FLOCAL9,
	CCN_STATUS_FACES_OBJECT_FLOCAL10,
	CCN_STATUS_FACES_OBJECT_FLOCAL11,
	CCN_STATUS_FACES_OBJECT_FLOCAL12,
	CCN_STATUS_FACES_OBJECT_FLOCAL13,
	CCN_STATUS_FACES_OBJECT_FPENDING0,
	CCN_STATUS_FACES_OBJECT_FPENDING1,
	CCN_STATUS_FACES_OBJECT_FPENDING2,
	CCN_STATUS_FACES_OBJECT_FPENDING3,
	CCN_STATUS_FACES_OBJECT_FPENDING4,
	CCN_STATUS_FACES_OBJECT_FPENDING5,
	CCN_STATUS_FACES_OBJECT_FPENDING6,
	CCN_STATUS_FACES_OBJECT_FPENDING7,
	CCN_STATUS_FACES_OBJECT_FPENDING8,
	CCN_STATUS_FACES_OBJECT_FPENDING9,
	CCN_STATUS_FACES_OBJECT_FPENDING10,
	CCN_STATUS_FACES_OBJECT_FPENDING11,
	CCN_STATUS_FACES_OBJECT_FPENDING12,
	CCN_STATUS_FACES_OBJECT_FPENDING13,
	CCN_STATUS_FACES_OBJECT_FREMOTE0,
	CCN_STATUS_FACES_OBJECT_FREMOTE1,
	CCN_STATUS_FACES_OBJECT_FREMOTE2,
	CCN_STATUS_FACES_OBJECT_FREMOTE3,
	CCN_STATUS_FACES_OBJECT_FREMOTE4,
	CCN_STATUS_FACES_OBJECT_FREMOTE5,
	CCN_STATUS_FACES_OBJECT_FREMOTE6,
	CCN_STATUS_FACES_OBJECT_FREMOTE7,
	CCN_STATUS_FACES_OBJECT_FREMOTE8,
	CCN_STATUS_FACES_OBJECT_FREMOTE9,
	CCN_STATUS_FACES_OBJECT_FREMOTE10,
	CCN_STATUS_FACES_OBJECT_FREMOTE11,
	CCN_STATUS_FACES_OBJECT_FREMOTE12,
	CCN_STATUS_FACES_OBJECT_FREMOTE13,
	CCN_STATUS_FACES_OBJECT_FHOST0,
	CCN_STATUS_FACES_OBJECT_FHOST1,
	CCN_STATUS_FACES_OBJECT_FHOST2,
	CCN_STATUS_FACES_OBJECT_FHOST3,
	CCN_STATUS_FACES_OBJECT_FHOST4,
	CCN_STATUS_FACES_OBJECT_FHOST5,
	CCN_STATUS_FACES_OBJECT_FHOST6,
	CCN_STATUS_FACES_OBJECT_FHOST7,
	CCN_STATUS_FACES_OBJECT_FHOST8,
	CCN_STATUS_FACES_OBJECT_FHOST9,
	CCN_STATUS_FACES_OBJECT_FHOST10,
	CCN_STATUS_FACES_OBJECT_FHOST11,
	CCN_STATUS_FACES_OBJECT_FHOST12,
	CCN_STATUS_FACES_OBJECT_FHOST13,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP0,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP1,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP2,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP3,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP4,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP5,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP6,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP7,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP8,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP9,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP10,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP11,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP12,
	CCN_STATUS_FACES_OBJECT_FTIMESTAMP13,
	CCN_STATUS_FACES_MAX_OBJECTS
};

enum ccn_mib_status_faces_activity_rates_objects {
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE0 = 0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST8,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP0,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP1,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP2,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP3,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP4,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP5,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP6,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP7,
	CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP8,
	CCN_STATUS_FACE_ACTIVITY_RATES_MAX_OBJECTS
};

enum ccn_mib_status_forwarding_objects {
	CCN_STATUS_FORWARDING_OBJECT_FWFACE0 = 0,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE1,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE2,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE3,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE4,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE5,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE6,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE7,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE8,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE9,
	CCN_STATUS_FORWARDING_OBJECT_FWFACE10,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS0,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS1,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS2,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS3,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS4,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS5,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS6,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS7,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS8,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS9,
	CCN_STATUS_FORWARDING_OBJECT_FWFLAGS10,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH0,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH1,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH2,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH3,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH4,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH5,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH6,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH7,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH8,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH9,
	CCN_STATUS_FORWARDING_OBJECT_FWPATH10,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES0,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES1,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES2,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES3,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES4,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES5,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES6,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES7,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES8,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES9,
	CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES10,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST0,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST1,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST2,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST3,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST4,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST5,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST6,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST7,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST8,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST9,
	CCN_STATUS_FORWARDING_OBJECT_FWHOST10,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP0,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP1,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP2,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP3,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP4,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP5,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP6,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP7,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP8,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP9,
	CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP10,
	CCN_STATUS_FORWARDING_MAX_OBJECTS
};

//Array de nome do Objeto da estrutura Pai de ccnSystem e ccndStatus

const char * ccnMibParentObjectName[CCN_MAX_PARENT_OBJECTS] = {
		"ccnSystem",
		"ccndStatus/contentItems",
		"ccndStatus/interests",
		"ccndStatus/interestTotals",
		"ccndStatus/faces",
		"ccndStatus/faceActivityRates",
		"ccndStatus/forwarding"
};

const char * ccnMibSystemObjectName[CCN_SYSTEM_MAX_OBJECTS] = {
		"ccnsysName",
		"ccnsysUptime",
		"ccnsysLoads",
		"ccnsysTotalram",
		"ccnsysFreeram",
		"ccnsysSharedram",
		"ccnsysBufferram",
		"ccnsysTotalswap",
		"ccnsysFreeswap",
		"ccnsysProcs",
		"ccnsysTotalhigh",
		"ccnsysFreehigh",
		"ccnsysMemunit",
		"ccnsysCharf"

};

//Array de valor para os Objetos de ccnSystem
char * ccnMibSystemObjectValue[CCN_SYSTEM_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/contentItems
const char * ccnMibStatusContentItemsObjectName[CCN_STATUS_CONTENT_ITEMS_MAX_OBJECTS] = {
		"ciAccessioned",
		"ciDuplicate",
		"ciSent",
		"ciSparse",
		"ciStale",
		"ciStored",
		"ciHost",
		"ciTimestamp"

};

//Array de valor para os Objetos de ccndStatus/contentItems
char * ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/interests
const char * ccnMibStatusInterestsObjectName[CCN_STATUS_INTERESTS_MAX_OBJECTS] = {
		"iNames",
		"iNoted",
		"iPending",
		"iPropagating",
		"iHost",
		"iTimestamp"
};

//Array de valor para os Objetos de ccndStatus/interests
char * ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/interestsTotals
const char * ccnMibStatusInterestTotalsObjectName[CCN_STATUS_INTEREST_TOTALS_MAX_OBJECTS] = {
		"itAccepted",
		"itDropped",
		"itSent",
		"itStuffed",
		"itHost",
		"itTimestamp"
};

//Array de valor para os Objetos de ccndStatus/interestsTotals
char * ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/faces
const char * ccnMibStatusFacesObjectName[CCN_STATUS_FACES_MAX_OBJECTS] = {
		"fFace0",
		"fFace1",
		"fFace2",
		"fFace3",
		"fFace4",
		"fFace5",
		"fFace6",
		"fFace7",
		"fFace8",
		"fFace9",
		"fFace10",
		"fFace11",
		"fFace12",
		"fFace13",
		"fFlags0",
		"fFlags1",
		"fFlags2",
		"fFlags3",
		"fFlags4",
		"fFlags5",
		"fFlags6",
		"fFlags7",
		"fFlags8",
		"fFlags9",
		"fFlags10",
		"fFlags11",
		"fFlags12",
		"fFlags13",
		"fLocal0",
		"fLocal1",
		"fLocal2",
		"fLocal3",
		"fLocal4",
		"fLocal5",
		"fLocal6",
		"fLocal7",
		"fLocal8",
		"fLocal9",
		"fLocal10",
		"fLocal11",
		"fLocal12",
		"fLocal13",
		"fPending0",
		"fPending1",
		"fPending2",
		"fPending3",
		"fPending4",
		"fPending5",
		"fPending6",
		"fPending7",
		"fPending8",
		"fPending9",
		"fPending10",
		"fPending11",
		"fPending12",
		"fPending13",
		"fRemote0",
		"fRemote1",
		"fRemote2",
		"fRemote3",
		"fRemote4",
		"fRemote5",
		"fRemote6",
		"fRemote7",
		"fRemote8",
		"fRemote9",
		"fRemote10",
		"fRemote11",
		"fRemote12",
		"fRemote13",
		"fHost0",
		"fHost1",
		"fHost2",
		"fHost3",
		"fHost4",
		"fHost5",
		"fHost6",
		"fHost7",
		"fHost8",
		"fHost9",
		"fHost10",
		"fHost11",
		"fHost12",
		"fHost13",
		"fTimestamp0",
		"fTimestamp1",
		"fTimestamp2",
		"fTimestamp3",
		"fTimestamp4",
		"fTimestamp5",
		"fTimestamp6",
		"fTimestamp7",
		"fTimestamp8",
		"fTimestamp9",
		"fTimestamp10",
		"fTimestamp11",
		"fTimestamp12",
		"fTimestamp13"
};

//Array de valor para os Objetos de faces
char * ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/faceActivityRates
const char * ccnMibStatusfaceActivityRatesObjectName[CCN_STATUS_FACE_ACTIVITY_RATES_MAX_OBJECTS] = {
		"farFace0",
		"farFace1",
		"farFace2",
		"farFace3",
		"farFace4",
		"farFace5",
		"farFace6",
		"farFace7",
		"farFace8",
		"farBytesIn0",
		"farBytesIn1",
		"farBytesIn2",
		"farBytesIn3",
		"farBytesIn4",
		"farBytesIn5",
		"farBytesIn6",
		"farBytesIn7",
		"farBytesIn8",
		"farBytesOut0",
		"farBytesOut1",
		"farBytesOut2",
		"farBytesOut3",
		"farBytesOut4",
		"farBytesOut5",
		"farBytesOut6",
		"farBytesOut7",
		"farBytesOut8",
		"farReceivedData0",
		"farReceivedData1",
		"farReceivedData2",
		"farReceivedData3",
		"farReceivedData4",
		"farReceivedData5",
		"farReceivedData6",
		"farReceivedData7",
		"farReceivedData8",
		"farSentData0",
		"farSentData1",
		"farSentData2",
		"farSentData3",
		"farSentData4",
		"farSentData5",
		"farSentData6",
		"farSentData7",
		"farSentData8",
		"farInterestsReceived0",
		"farInterestsReceived1",
		"farInterestsReceived2",
		"farInterestsReceived3",
		"farInterestsReceived4",
		"farInterestsReceived5",
		"farInterestsReceived6",
		"farInterestsReceived7",
		"farInterestsReceived8",
		"farInterestsSent0",
		"farInterestsSent1",
		"farInterestsSent2",
		"farInterestsSent3",
		"farInterestsSent4",
		"farInterestsSent5",
		"farInterestsSent6",
		"farInterestsSent7",
		"farInterestsSent8",
		"farHost0",
		"farHost1",
		"farHost2",
		"farHost3",
		"farHost4",
		"farHost5",
		"farHost6",
		"farHost7",
		"farHost8",
		"farTimestamp0",
		"farTimestamp1",
		"farTimestamp2",
		"farTimestamp3",
		"farTimestamp4",
		"farTimestamp5",
		"farTimestamp6",
		"farTimestamp7",
		"farTimestamp8"
};

//Array de valor para os Objetos de ccndStatus/faceActivityRates
char * ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_MAX_OBJECTS];

//Array de nome do Objeto de ccndStatus/forwarding
const char * ccnMibStatusForwardingObjectName[CCN_STATUS_FORWARDING_MAX_OBJECTS] = {
		"fwFace0",
		"fwFace1",
		"fwFace2",
		"fwFace3",
		"fwFace4",
		"fwFace5",
		"fwFace6",
		"fwFace7",
		"fwFace8",
		"fwFace9",
		"fwFace10",
		"fwFlags0",
		"fwFlags1",
		"fwFlags2",
		"fwFlags3",
		"fwFlags4",
		"fwFlags5",
		"fwFlags6",
		"fwFlags7",
		"fwFlags8",
		"fwFlags9",
		"fwFlags10",
		"fwPath0",
		"fwPath1",
		"fwPath2",
		"fwPath3",
		"fwPath4",
		"fwPath5",
		"fwPath6",
		"fwPath7",
		"fwPath8",
		"fwPath9",
		"fwPath10",
		"fwExpires0",
		"fwExpires1",
		"fwExpires2",
		"fwExpires3",
		"fwExpires4",
		"fwExpires5",
		"fwExpires6",
		"fwExpires7",
		"fwExpires8",
		"fwExpires9",
		"fwExpires10",
		"fwHost0",
		"fwHost1",
		"fwHost2",
		"fwHost3",
		"fwHost4",
		"fwHost5",
		"fwHost6",
		"fwHost7",
		"fwHost8",
		"fwHost9",
		"fwHost10",
		"fwTimestamp0",
		"fwTimestamp1",
		"fwTimestamp2",
		"fwTimestamp3",
		"fwTimestamp4",
		"fwTimestamp5",
		"fwTimestamp6",
		"fwTimestamp7",
		"fwTimestamp8",
		"fwTimestamp9",
		"fwTimestamp10"
};

//Array de valor para os Objetos de ccndStatus/forwarding
char * ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_MAX_OBJECTS];

//Funcao para inicializar os valores de cada objeto das Mibs

void initializeMibObjectValue(){

	const long minute = 60;
	const long hour = minute * 60;
	const long day = hour * 60;
	const double MB = 1024 * 1024;

	struct sysinfo sys_info;
		if(sysinfo(&sys_info) != 0)
		    perror("sys_info");

//valores de cada objeto de ccnSystem
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_NAME] = getenv("NE_NAME");
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME] = malloc(50);
//		   	snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld days, %ld:%02ld:%02ld\n", sys_info.uptime / day, (sys_info.uptime % day) / hour,  (sys_info.uptime % day) / minute, sys_info.uptime % minute);
//	snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld days, %ld:%02ld:%02ld\n", sys_info.uptime / day, sys_info.uptime / 3600, ((sys_info.uptime - ((3600 * (sys_info.uptime / 3600))/60; (((sys_info.uptime - (3600 * (sys_info.uptime / 3600))/60) - (((sys_info.uptime - (3600 * (sys_info.uptime / 3600))/60);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld seconds", sys_info.uptime);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_LOADS] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_LOADS], 50, "LOADS: %d", sys_info.loads);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALRAM] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALRAM], 50, "TOTAL RAM: %d MB", sys_info.totalram / MB);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREERAM] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREERAM], 50, "FREE RAM: %d MB", sys_info.freeram / MB);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_SHAREDRAM] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_SHAREDRAM], 50, "SHARED RAM: %d", sys_info.sharedram);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_BUFFERRAM] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_BUFFERRAM], 50, "BUFFERRAM: %d", sys_info.bufferram);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALSWAP] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALSWAP], 50, "TOTAL SWAP: %d", sys_info.totalswap);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREESWAP] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREESWAP], 50, "FREE SWAP: %d", sys_info.freeswap);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_PROCS] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_PROCS], 50, "PROCS: %d", sys_info.procs);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALHIGH] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALHIGH], 50, "TOTAL HIGH: %d", sys_info.totalhigh);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREELHIGH] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREELHIGH], 50, "FREE HIGH: %d", sys_info.freehigh);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_MEMUNIT] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_MEMUNIT], 50, "MEM UNIT: %d", sys_info.mem_unit);
	ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_CHARF] = malloc(50);
			snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_CHARF], 50, "CHAR_F: %d", sys_info._f);

//leitura de arquivos com conteudo de cada objeto de ccndStatus/contentItems

	char * hostname = getenv("NE_NAME");

	char path_ciaccessioned0[100];
	sprintf(path_ciaccessioned0, "/home/user/ccndStatus-ObjectValues/%s.content_items.accessioned.0", hostname);
	FILE *file_ciaccessioned0;
	file_ciaccessioned0 = fopen(path_ciaccessioned0, "r");
	char object_ciaccessioned0[100];

	char path_ciduplicate0[100];
	sprintf(path_ciduplicate0, "/home/user/ccndStatus-ObjectValues/%s.content_items.duplicate.0", hostname);
	FILE *file_ciduplicate0;
	file_ciduplicate0 = fopen(path_ciduplicate0, "r");
	char object_ciduplicate0[100];

	char path_cisent0[100];
	sprintf(path_cisent0, "/home/user/ccndStatus-ObjectValues/%s.content_items.sent.0", hostname);
	FILE *file_cisent0;
	file_cisent0 = fopen(path_cisent0, "r");
	char object_cisent0[100];

	char path_cisparse0[100];
	sprintf(path_cisparse0, "/home/user/ccndStatus-ObjectValues/%s.content_items.sparse.0", hostname);
	FILE *file_cisparse0;
	file_cisparse0 = fopen(path_cisparse0, "r");
	char object_cisparse0[100];

	char path_cistale0[100];
	sprintf(path_cistale0, "/home/user/ccndStatus-ObjectValues/%s.content_items.stale.0", hostname);
	FILE *file_cistale0;
	file_cistale0 = fopen(path_cistale0, "r");
	char object_cistale0[100];

	char path_cistored0[100];
	sprintf(path_cistored0, "/home/user/ccndStatus-ObjectValues/%s.content_items.stored.0", hostname);
	FILE *file_cistored0;
	file_cistored0 = fopen(path_cistored0, "r");
	char object_cistored0[100];

	char path_cihostname0[100];
	sprintf(path_cihostname0, "/home/user/ccndStatus-ObjectValues/%s.content_items.hostname.0", hostname);
	FILE *file_cihostname0;
	file_cihostname0 = fopen(path_cihostname0, "r");
	char object_cihostname0[100];

	char path_citime0[100];
	sprintf(path_citime0, "/home/user/ccndStatus-ObjectValues/%s.content_items.time.0", hostname);
	FILE *file_citime0;
	file_citime0 = fopen(path_citime0, "r");
	char object_citime0[100];

//valores de cada objeto de ccndStatus/contentItems
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIACCESSIONED] = strdup (fgets (object_ciaccessioned0, sizeof(object_ciaccessioned0), file_ciaccessioned0)); fclose(file_ciaccessioned0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIDUPLICATE] = strdup (fgets (object_ciduplicate0, sizeof(object_ciduplicate0), file_ciduplicate0)); fclose(file_ciduplicate0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISENT] = strdup (fgets (object_cisent0, sizeof(object_cisent0), file_cisent0)); fclose(file_cisent0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISPARSE] = strdup (fgets (object_cisparse0, sizeof(object_cisparse0), file_cisparse0)); fclose(file_cisparse0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTALE] = strdup (fgets (object_cistale0, sizeof(object_cistale0), file_cistale0)); fclose(file_cistale0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTORED] = strdup (fgets (object_cistored0, sizeof(object_cistored0), file_cistored0)); fclose(file_cistored0);
    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIHOST] = strdup (fgets (object_cihostname0, sizeof(object_cihostname0), file_cihostname0)); fclose(file_cihostname0);
   	ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CITIMESTAMP] = strdup (fgets (object_citime0, sizeof(object_citime0), file_citime0)); fclose(file_citime0);

//leitura de arquivos com conteudo de cada objeto de ccndStatus/interests

   	char path_inames0[100];
   	sprintf(path_inames0, "/home/user/ccndStatus-ObjectValues/%s.interests.names.0", hostname);
   	FILE *file_inames0;
   	file_inames0 = fopen(path_inames0, "r");
   	char object_inames0[100];

   	char path_inoted0[100];
   	sprintf(path_inoted0, "/home/user/ccndStatus-ObjectValues/%s.interests.noted.0", hostname);
   	FILE *file_inoted0;
   	file_inoted0 = fopen(path_inoted0, "r");
   	char object_inoted0[100];

   	char path_ipending0[100];
   	sprintf(path_ipending0, "/home/user/ccndStatus-ObjectValues/%s.interests.pending.0", hostname);
   	FILE *file_ipending0;
   	file_ipending0 = fopen(path_ipending0, "r");
   	char object_ipending0[100];

   	char path_ipropagating0[100];
   	sprintf(path_ipropagating0, "/home/user/ccndStatus-ObjectValues/%s.interests.propagating.0", hostname);
   	FILE *file_ipropagating0;
   	file_ipropagating0 = fopen(path_ipropagating0, "r");
   	char object_ipropagating0[100];

   	char path_ihostname0[100];
   	sprintf(path_ihostname0, "/home/user/ccndStatus-ObjectValues/%s.interests.hostname.0", hostname);
   	FILE *file_ihostname0;
   	file_ihostname0 = fopen(path_ihostname0, "r");
   	char object_ihostname0[100];

   	char path_itime0[100];
   	sprintf(path_itime0, "/home/user/ccndStatus-ObjectValues/%s.interests.time.0", hostname);
   	FILE *file_itime0;
   	file_itime0 = fopen(path_itime0, "r");
   	char object_itime0[100];

//valores de cada objeto de ccndStatus/interests
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_INAMES] = strdup (fgets (object_inames0, sizeof(object_inames0), file_inames0)); fclose(file_inames0);
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_INOTED] = strdup (fgets (object_inoted0, sizeof(object_inoted0), file_inoted0)); fclose(file_inoted0);
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IPENDING] = strdup (fgets (object_ipending0, sizeof(object_ipending0), file_ipending0)); fclose(file_ipending0);
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IPROPAGATING] = strdup (fgets (object_ipropagating0, sizeof(object_ipropagating0), file_ipropagating0)); fclose(file_ipropagating0);
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IHOST] = strdup (fgets (object_ihostname0, sizeof(object_ihostname0), file_ihostname0)); fclose(file_ihostname0);
   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_ITIMESTAMP] = strdup (fgets (object_itime0, sizeof(object_itime0), file_itime0)); fclose(file_itime0);

//leitura de arquivos com conteudo de cada objeto de ccndStatus/interestsTotals

   	char path_itaccepted0[100];
 	sprintf(path_itaccepted0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.accepted.0", hostname);
   	FILE *file_itaccepted0;
   	file_itaccepted0 = fopen(path_itaccepted0, "r");
   	char object_itaccepted0[100];

   	char path_itdropped0[100];
   	sprintf(path_itdropped0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.dropped.0", hostname);
   	FILE *file_itdropped0;
   	file_itdropped0 = fopen(path_itdropped0, "r");
   	char object_itdropped0[100];

   	char path_itsent0[100];
   	sprintf(path_itsent0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.sent.0", hostname);
   	FILE *file_itsent0;
   	file_itsent0 = fopen(path_itsent0, "r");
   	char object_itsent0[100];

   	char path_itstuffed0[100];
   	sprintf(path_itstuffed0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.stuffed.0", hostname);
   	FILE *file_itstuffed0;
   	file_itstuffed0 = fopen(path_itstuffed0, "r");
   	char object_itstuffed0[100];

   	char path_ithostname0[100];
   	sprintf(path_ithostname0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.hostname.0", hostname);
  	FILE *file_ithostname0;
	file_ithostname0 = fopen(path_ithostname0, "r");
   	char object_ithostname0[100];

   	char path_ittime0[100];
   	sprintf(path_ittime0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.time.0", hostname);
   	FILE *file_ittime0;
   	file_ittime0 = fopen(path_ittime0, "r");
   	char object_ittime0[100];

//valores de cada objeto de ccndStatus/interestsTotals
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITACCEPTED] = strdup (fgets (object_itaccepted0, sizeof(object_itaccepted0), file_itaccepted0)); fclose(file_itaccepted0);
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITDROPPED] = strdup (fgets (object_itdropped0, sizeof(object_itdropped0), file_itdropped0)); fclose(file_itdropped0);
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSENT] = strdup (fgets (object_itsent0, sizeof(object_itsent0), file_itsent0)); fclose(file_itsent0);
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSTUFFED] = strdup (fgets (object_itstuffed0, sizeof(object_itstuffed0), file_itstuffed0)); fclose(file_itstuffed0);
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITHOST] = strdup (fgets (object_ithostname0, sizeof(object_ithostname0), file_ithostname0)); fclose(file_ithostname0);
   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITTIMESTAMP] = strdup (fgets (object_ittime0, sizeof(object_ittime0), file_ittime0)); fclose(file_ittime0);

//leitura de arquivos com conteudo de cada objeto de ccndStatus/faces

   	char path_fface0[100];
    sprintf(path_fface0, "/home/user/ccndStatus-ObjectValues/%s.faces.face.0", hostname);
   	FILE *file_fface0;
   	file_fface0 = fopen(path_fface0, "r");
   	char object_fface0[100];

   	if (file_fface0 == NULL) {
   	file_fface0 = fopen(path_fface0, "w+");
   	fprintf(file_fface0,"face0=NULL\n");
   	rewind(file_fface0);
   	}

   	char path_fface1[100];
    sprintf(path_fface1, "/home/user/ccndStatus-ObjectValues/%s.faces.face.1", hostname);
   	FILE *file_fface1;
   	file_fface1 = fopen(path_fface1, "r");
   	char object_fface1[100];

   	if (file_fface1 == NULL) {
   	file_fface1 = fopen(path_fface1, "w+");
   	fprintf(file_fface1,"face1=NULL\n");
   	rewind(file_fface1);
   	}

   	char path_fface2[100];
    sprintf(path_fface2, "/home/user/ccndStatus-ObjectValues/%s.faces.face.2", hostname);
   	FILE *file_fface2;
   	file_fface2 = fopen(path_fface2, "r");
   	char object_fface2[100];

   	if (file_fface2 == NULL) {
   	file_fface2 = fopen(path_fface2, "w+");
   	fprintf(file_fface2,"face2=NULL\n");
   	rewind(file_fface2);
   	}

   	char path_fface3[100];
    sprintf(path_fface3, "/home/user/ccndStatus-ObjectValues/%s.faces.face.3", hostname);
   	FILE *file_fface3;
   	file_fface3 = fopen(path_fface3, "r");
   	char object_fface3[100];

   	if (file_fface3 == NULL) {
   	file_fface3 = fopen(path_fface3, "w+");
   	fprintf(file_fface3,"face3=NULL\n");
   	rewind(file_fface3);
   	}

   	char path_fface4[100];
    sprintf(path_fface4, "/home/user/ccndStatus-ObjectValues/%s.faces.face.4", hostname);
   	FILE *file_fface4;
   	file_fface4 = fopen(path_fface4, "r");
   	char object_fface4[100];

   	if (file_fface4 == NULL) {
   	file_fface4 = fopen(path_fface4, "w+");
   	fprintf(file_fface4,"face4=NULL\n");
   	rewind(file_fface4);
   	}

   	char path_fface5[100];
    sprintf(path_fface5, "/home/user/ccndStatus-ObjectValues/%s.faces.face.5", hostname);
   	FILE *file_fface5;
   	file_fface5 = fopen(path_fface5, "r");
   	char object_fface5[100];

   	if (file_fface5 == NULL) {
   	file_fface5 = fopen(path_fface5, "w+");
   	fprintf(file_fface5,"face5=NULL\n");
   	rewind(file_fface5);
   	}

   	char path_fface6[100];
    sprintf(path_fface6, "/home/user/ccndStatus-ObjectValues/%s.faces.face.6", hostname);
   	FILE *file_fface6;
   	file_fface6 = fopen(path_fface6, "r");
   	char object_fface6[100];

   	if (file_fface6 == NULL) {
   	file_fface6 = fopen(path_fface6, "w+");
   	fprintf(file_fface6,"face6=NULL\n");
   	rewind(file_fface6);
   	}

   	char path_fface7[100];
    sprintf(path_fface7, "/home/user/ccndStatus-ObjectValues/%s.faces.face.7", hostname);
   	FILE *file_fface7;
   	file_fface7 = fopen(path_fface7, "r");
   	char object_fface7[100];

   	if (file_fface7 == NULL) {
   	file_fface7 = fopen(path_fface7, "w+");
   	fprintf(file_fface7,"face7=NULL\n");
   	rewind(file_fface7);
   	}

   	char path_fface8[100];
    sprintf(path_fface8, "/home/user/ccndStatus-ObjectValues/%s.faces.face.8", hostname);
   	FILE *file_fface8;
   	file_fface8 = fopen(path_fface8, "r");
   	char object_fface8[100];

   	if (file_fface8 == NULL) {
   	file_fface8 = fopen(path_fface8, "w+");
   	fprintf(file_fface8,"face8=NULL\n");
   	rewind(file_fface8);
   	}

   	char path_fface9[100];
    sprintf(path_fface9, "/home/user/ccndStatus-ObjectValues/%s.faces.face.9", hostname);
   	FILE *file_fface9;
   	file_fface9 = fopen(path_fface9, "r");
   	char object_fface9[100];

   	if (file_fface9 == NULL) {
   	file_fface9 = fopen(path_fface9, "w+");
   	fprintf(file_fface9,"face9=NULL\n");
   	rewind(file_fface9);
   	}

   	char path_fface10[100];
    sprintf(path_fface10, "/home/user/ccndStatus-ObjectValues/%s.faces.face.10", hostname);
   	FILE *file_fface10;
   	file_fface10 = fopen(path_fface10, "r");
   	char object_fface10[100];

   	if (file_fface10 == NULL) {
   	file_fface10 = fopen(path_fface10, "w+");
   	fprintf(file_fface10,"face10=NULL\n");
   	rewind(file_fface10);
   	}

   	char path_fface11[100];
    sprintf(path_fface11, "/home/user/ccndStatus-ObjectValues/%s.faces.face.11", hostname);
   	FILE *file_fface11;
   	file_fface11 = fopen(path_fface11, "r");
   	char object_fface11[100];

   	if (file_fface11 == NULL) {
   	file_fface11 = fopen(path_fface11, "w+");
   	fprintf(file_fface11,"face11=NULL\n");
   	rewind(file_fface11);
   	}

   	char path_fface12[100];
    sprintf(path_fface12, "/home/user/ccndStatus-ObjectValues/%s.faces.face.12", hostname);
   	FILE *file_fface12;
   	file_fface12 = fopen(path_fface12, "r");
   	char object_fface12[100];

   	if (file_fface12 == NULL) {
   	file_fface12 = fopen(path_fface12, "w+");
   	fprintf(file_fface12,"face12=NULL\n");
   	rewind(file_fface12);
   	}

   	char path_fface13[100];
    sprintf(path_fface13, "/home/user/ccndStatus-ObjectValues/%s.faces.face.13", hostname);
   	FILE *file_fface13;
   	file_fface13 = fopen(path_fface13, "r");
   	char object_fface13[100];

   	if (file_fface13 == NULL) {
   	file_fface13 = fopen(path_fface13, "w+");
   	fprintf(file_fface13,"face13=NULL\n");
   	rewind(file_fface13);
   	}

   	char path_fflags0[100];
   	sprintf(path_fflags0, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.0", hostname);
   	FILE *file_fflags0;
   	file_fflags0 = fopen(path_fflags0, "r");
   	char object_fflags0[100];

   	if (file_fflags0 == NULL) {
   	file_fflags0 = fopen(path_fflags0, "w+");
   	fprintf(file_fflags0,"flags0=NULL\n");
   	rewind(file_fflags0);
   	}

   	char path_fflags1[100];
   	sprintf(path_fflags1, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.1", hostname);
   	FILE *file_fflags1;
   	file_fflags1 = fopen(path_fflags1, "r");
   	char object_fflags1[100];

   	if (file_fflags1 == NULL) {
   	file_fflags1 = fopen(path_fflags1, "w+");
   	fprintf(file_fflags1,"flags1=NULL\n");
   	rewind(file_fflags1);
   	}

   	char path_fflags2[100];
   	sprintf(path_fflags2, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.2", hostname);
   	FILE *file_fflags2;
   	file_fflags2 = fopen(path_fflags2, "r");
   	char object_fflags2[100];

   	if (file_fflags2 == NULL) {
   	file_fflags2 = fopen(path_fflags2, "w+");
   	fprintf(file_fflags2,"flags2=NULL\n");
   	rewind(file_fflags2);
   	}

   	char path_fflags3[100];
   	sprintf(path_fflags3, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.3", hostname);
   	FILE *file_fflags3;
   	file_fflags3 = fopen(path_fflags3, "r");
   	char object_fflags3[100];

   	if (file_fflags3 == NULL) {
   	file_fflags3 = fopen(path_fflags3, "w+");
   	fprintf(file_fflags3,"flags3=NULL\n");
   	rewind(file_fflags3);
   	}

   	char path_fflags4[100];
   	sprintf(path_fflags4, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.4", hostname);
   	FILE *file_fflags4;
   	file_fflags4 = fopen(path_fflags4, "r");
   	char object_fflags4[100];

   	if (file_fflags4 == NULL) {
   	file_fflags4 = fopen(path_fflags4, "w+");
   	fprintf(file_fflags4,"flags4=NULL\n");
   	rewind(file_fflags4);
   	}

   	char path_fflags5[100];
   	sprintf(path_fflags5, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.5", hostname);
   	FILE *file_fflags5;
   	file_fflags5 = fopen(path_fflags5, "r");
   	char object_fflags5[100];

   	if (file_fflags5 == NULL) {
   	file_fflags5 = fopen(path_fflags5, "w+");
   	fprintf(file_fflags5,"flags5=NULL\n");
   	rewind(file_fflags5);
   	}

   	char path_fflags6[100];
   	sprintf(path_fflags6, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.6", hostname);
   	FILE *file_fflags6;
   	file_fflags6 = fopen(path_fflags6, "r");
   	char object_fflags6[100];

   	if (file_fflags6 == NULL) {
   	file_fflags6 = fopen(path_fflags6, "w+");
   	fprintf(file_fflags6,"flags6=NULL\n");
   	rewind(file_fflags6);
   	}

   	char path_fflags7[100];
   	sprintf(path_fflags7, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.7", hostname);
   	FILE *file_fflags7;
   	file_fflags7 = fopen(path_fflags7, "r");
   	char object_fflags7[100];

   	if (file_fflags7 == NULL) {
   	file_fflags7 = fopen(path_fflags7, "w+");
   	fprintf(file_fflags7,"flags7=NULL\n");
   	rewind(file_fflags7);
   	}

   	char path_fflags8[100];
   	sprintf(path_fflags8, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.8", hostname);
   	FILE *file_fflags8;
   	file_fflags8 = fopen(path_fflags8, "r");
   	char object_fflags8[100];

   	if (file_fflags8 == NULL) {
   	file_fflags8 = fopen(path_fflags8, "w+");
   	fprintf(file_fflags8,"flags8=NULL\n");
   	rewind(file_fflags8);
   	}

   	char path_fflags9[100];
   	sprintf(path_fflags9, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.9", hostname);
   	FILE *file_fflags9;
   	file_fflags9 = fopen(path_fflags9, "r");
   	char object_fflags9[100];

   	if (file_fflags9 == NULL) {
   	file_fflags9 = fopen(path_fflags9, "w+");
   	fprintf(file_fflags9,"flags9=NULL\n");
   	rewind(file_fflags9);
   	}

   	char path_fflags10[100];
   	sprintf(path_fflags10, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.10", hostname);
   	FILE *file_fflags10;
   	file_fflags10 = fopen(path_fflags10, "r");
   	char object_fflags10[100];

   	if (file_fflags10 == NULL) {
   	file_fflags10 = fopen(path_fflags10, "w+");
   	fprintf(file_fflags10,"flags10=NULL\n");
   	rewind(file_fflags10);
   	}

   	char path_fflags11[100];
   	sprintf(path_fflags11, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.11", hostname);
   	FILE *file_fflags11;
   	file_fflags11 = fopen(path_fflags11, "r");
   	char object_fflags11[100];

   	if (file_fflags11 == NULL) {
   	file_fflags11 = fopen(path_fflags11, "w+");
   	fprintf(file_fflags11,"flags11=NULL\n");
   	rewind(file_fflags11);
   	}

   	char path_fflags12[100];
   	sprintf(path_fflags12, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.12", hostname);
   	FILE *file_fflags12;
   	file_fflags12 = fopen(path_fflags12, "r");
   	char object_fflags12[100];

   	if (file_fflags12 == NULL) {
   	file_fflags12 = fopen(path_fflags12, "w+");
   	fprintf(file_fflags12,"flags12=NULL\n");
   	rewind(file_fflags12);
   	}

   	char path_fflags13[100];
   	sprintf(path_fflags13, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.13", hostname);
   	FILE *file_fflags13;
   	file_fflags13 = fopen(path_fflags13, "r");
   	char object_fflags13[100];

   	if (file_fflags13 == NULL) {
   	file_fflags13 = fopen(path_fflags13, "w+");
   	fprintf(file_fflags13,"flags13=NULL\n");
   	rewind(file_fflags13);
   	}

   	char path_flocal0[100];
   	sprintf(path_flocal0, "/home/user/ccndStatus-ObjectValues/%s.faces.local.0", hostname);
   	FILE *file_flocal0;
   	file_flocal0 = fopen(path_flocal0, "r");
   	char object_flocal0[100];

  	if (file_flocal0 == NULL) {
   	file_flocal0 = fopen(path_flocal0, "w+");
   	fprintf(file_flocal0,"local0=NULL\n");
   	rewind(file_flocal0);
   	}

   	char path_flocal1[100];
   	sprintf(path_flocal1, "/home/user/ccndStatus-ObjectValues/%s.faces.local.1", hostname);
   	FILE *file_flocal1;
   	file_flocal1 = fopen(path_flocal1, "r");
   	char object_flocal1[100];

  	if (file_flocal1 == NULL) {
   	file_flocal1 = fopen(path_flocal1, "w+");
   	fprintf(file_flocal1,"local1=NULL\n");
   	rewind(file_flocal1);
   	}

    char path_flocal2[100];
   	sprintf(path_flocal2, "/home/user/ccndStatus-ObjectValues/%s.faces.local.2", hostname);
   	FILE *file_flocal2;
   	file_flocal2 = fopen(path_flocal2, "r");
   	char object_flocal2[100];

  	if (file_flocal2 == NULL) {
   	file_flocal2 = fopen(path_flocal2, "w+");
   	fprintf(file_flocal2,"local2=NULL\n");
   	rewind(file_flocal2);
   	}

   	char path_flocal3[100];
   	sprintf(path_flocal3, "/home/user/ccndStatus-ObjectValues/%s.faces.local.3", hostname);
   	FILE *file_flocal3;
   	file_flocal3 = fopen(path_flocal3, "r");
   	char object_flocal3[100];

  	if (file_flocal3 == NULL) {
   	file_flocal3 = fopen(path_flocal3, "w+");
   	fprintf(file_flocal3,"local3=NULL\n");
   	rewind(file_flocal3);
   	}

   	char path_flocal4[100];
   	sprintf(path_flocal4, "/home/user/ccndStatus-ObjectValues/%s.faces.local.4", hostname);
   	FILE *file_flocal4;
   	file_flocal4 = fopen(path_flocal4, "r");
   	char object_flocal4[100];

  	if (file_flocal4 == NULL) {
   	file_flocal4 = fopen(path_flocal4, "w+");
   	fprintf(file_flocal4,"local4=NULL\n");
   	rewind(file_flocal4);
   	}

   	char path_flocal5[100];
   	sprintf(path_flocal5, "/home/user/ccndStatus-ObjectValues/%s.faces.local.5", hostname);
   	FILE *file_flocal5;
   	file_flocal5 = fopen(path_flocal5, "r");
   	char object_flocal5[100];

  	if (file_flocal5 == NULL) {
   	file_flocal5 = fopen(path_flocal5, "w+");
   	fprintf(file_flocal5,"local5=NULL\n");
   	rewind(file_flocal5);
   	}

   	char path_flocal6[100];
   	sprintf(path_flocal6, "/home/user/ccndStatus-ObjectValues/%s.faces.local.6", hostname);
   	FILE *file_flocal6;
   	file_flocal6 = fopen(path_flocal6, "r");
   	char object_flocal6[100];

  	if (file_flocal6 == NULL) {
   	file_flocal6 = fopen(path_flocal6, "w+");
   	fprintf(file_flocal6,"local6=NULL\n");
   	rewind(file_flocal6);
   	}

   	char path_flocal7[100];
   	sprintf(path_flocal7, "/home/user/ccndStatus-ObjectValues/%s.faces.local.7", hostname);
    FILE *file_flocal7;
   	file_flocal7 = fopen(path_flocal7, "r");
   	char object_flocal7[100];

  	if (file_flocal7 == NULL) {
   	file_flocal7 = fopen(path_flocal7, "w+");
   	fprintf(file_flocal7,"local7=NULL\n");
   	rewind(file_flocal7);
   	}

   	char path_flocal8[100];
   	sprintf(path_flocal8, "/home/user/ccndStatus-ObjectValues/%s.faces.local.8", hostname);
   	FILE *file_flocal8;
   	file_flocal8 = fopen(path_flocal8, "r");
   	char object_flocal8[100];

  	if (file_flocal8 == NULL) {
   	file_flocal8 = fopen(path_flocal8, "w+");
   	fprintf(file_flocal8,"local8=NULL\n");
   	rewind(file_flocal8);
   	}

   	char path_flocal9[100];
   	sprintf(path_flocal9, "/home/user/ccndStatus-ObjectValues/%s.faces.local.9", hostname);
   	FILE *file_flocal9;
   	file_flocal9 = fopen(path_flocal9, "r");
   	char object_flocal9[100];

  	if (file_flocal9 == NULL) {
   	file_flocal9 = fopen(path_flocal9, "w+");
   	fprintf(file_flocal9,"local9=NULL\n");
   	rewind(file_flocal9);
   	}

   	char path_flocal10[100];
   	sprintf(path_flocal10, "/home/user/ccndStatus-ObjectValues/%s.faces.local.10", hostname);
   	FILE *file_flocal10;
   	file_flocal10 = fopen(path_flocal10, "r");
   	char object_flocal10[100];

  	if (file_flocal10 == NULL) {
   	file_flocal10 = fopen(path_flocal10, "w+");
   	fprintf(file_flocal10,"local10=NULL\n");
   	rewind(file_flocal10);
   	}

   	char path_flocal11[100];
   	sprintf(path_flocal11, "/home/user/ccndStatus-ObjectValues/%s.faces.local.11", hostname);
   	FILE *file_flocal11;
   	file_flocal11 = fopen(path_flocal11, "r");
   	char object_flocal11[100];

  	if (file_flocal11 == NULL) {
   	file_flocal11 = fopen(path_flocal11, "w+");
   	fprintf(file_flocal11,"local11=NULL\n");
   	rewind(file_flocal11);
   	}

   	char path_flocal12[100];
   	sprintf(path_flocal12, "/home/user/ccndStatus-ObjectValues/%s.faces.local.12", hostname);
   	FILE *file_flocal12;
   	file_flocal12 = fopen(path_flocal12, "r");
   	char object_flocal12[100];

  	if (file_flocal12 == NULL) {
   	file_flocal12 = fopen(path_flocal12, "w+");
   	fprintf(file_flocal12,"local12=NULL\n");
   	rewind(file_flocal12);
   	}

   	char path_flocal13[100];
   	sprintf(path_flocal13, "/home/user/ccndStatus-ObjectValues/%s.faces.local.13", hostname);
   	FILE *file_flocal13;
   	file_flocal13 = fopen(path_flocal13, "r");
   	char object_flocal13[100];

   	if (file_flocal13 == NULL) {
   	file_flocal13 = fopen(path_flocal13, "w+");
   	fprintf(file_flocal13,"local13=NULL\n");
   	rewind(file_flocal13);
   	}

   	char path_fpending0[100];
   	sprintf(path_fpending0, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.0", hostname);
   	FILE *file_fpending0;
   	file_fpending0 = fopen(path_fpending0, "r");
   	char object_fpending0[100];

  	if (file_fpending0 == NULL) {
   	file_fpending0 = fopen(path_fpending0, "w+");
   	fprintf(file_fpending0,"pending0=NULL\n");
   	rewind(file_fpending0);
   	}

   	char path_fpending1[100];
   	sprintf(path_fpending1, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.1", hostname);
   	FILE *file_fpending1;
   	file_fpending1 = fopen(path_fpending1, "r");
   	char object_fpending1[100];

 	if (file_fpending1 == NULL) {
   	file_fpending1 = fopen(path_fpending1, "w+");
   	fprintf(file_fpending1,"pending1=NULL\n");
   	rewind(file_fpending1);
   	}

   	char path_fpending2[100];
   	sprintf(path_fpending2, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.2", hostname);
   	FILE *file_fpending2;
   	file_fpending2 = fopen(path_fpending2, "r");
   	char object_fpending2[100];

 	if (file_fpending2 == NULL) {
   	file_fpending2 = fopen(path_fpending2, "w+");
   	fprintf(file_fpending2,"pending2=NULL\n");
   	rewind(file_fpending2);
   	}

   	char path_fpending3[100];
   	sprintf(path_fpending3, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.3", hostname);
   	FILE *file_fpending3;
   	file_fpending3 = fopen(path_fpending3, "r");
   	char object_fpending3[100];

 	if (file_fpending3 == NULL) {
   	file_fpending3 = fopen(path_fpending3, "w+");
   	fprintf(file_fpending3,"pending3=NULL\n");
   	rewind(file_fpending3);
   	}

   	char path_fpending4[100];
   	sprintf(path_fpending4, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.4", hostname);
   	FILE *file_fpending4;
   	file_fpending4 = fopen(path_fpending4, "r");
   	char object_fpending4[100];

 	if (file_fpending4 == NULL) {
   	file_fpending4 = fopen(path_fpending4, "w+");
   	fprintf(file_fpending4,"pending4=NULL\n");
   	rewind(file_fpending4);
   	}

   	char path_fpending5[100];
   	sprintf(path_fpending5, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.5", hostname);
   	FILE *file_fpending5;
   	file_fpending5 = fopen(path_fpending5, "r");
   	char object_fpending5[100];

 	if (file_fpending5 == NULL) {
   	file_fpending5 = fopen(path_fpending5, "w+");
   	fprintf(file_fpending5,"pending5=NULL\n");
   	rewind(file_fpending5);
   	}

   	char path_fpending6[100];
   	sprintf(path_fpending6, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.6", hostname);
   	FILE *file_fpending6;
   	file_fpending6 = fopen(path_fpending6, "r");
   	char object_fpending6[100];

 	if (file_fpending6 == NULL) {
   	file_fpending6 = fopen(path_fpending6, "w+");
   	fprintf(file_fpending6,"pending6=NULL\n");
   	rewind(file_fpending6);
   	}

   	char path_fpending7[100];
   	sprintf(path_fpending7, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.7", hostname);
   	FILE *file_fpending7;
   	file_fpending7 = fopen(path_fpending7, "r");
   	char object_fpending7[100];

 	if (file_fpending7 == NULL) {
   	file_fpending7 = fopen(path_fpending7, "w+");
   	fprintf(file_fpending7,"pending7=NULL\n");
   	rewind(file_fpending7);
   	}

   	char path_fpending8[100];
   	sprintf(path_fpending8, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.8", hostname);
   	FILE *file_fpending8;
   	file_fpending8 = fopen(path_fpending8, "r");
   	char object_fpending8[100];

 	if (file_fpending8 == NULL) {
   	file_fpending8 = fopen(path_fpending8, "w+");
   	fprintf(file_fpending8,"pending8=NULL\n");
   	rewind(file_fpending8);
   	}

   	char path_fpending9[100];
   	sprintf(path_fpending9, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.9", hostname);
   	FILE *file_fpending9;
   	file_fpending9 = fopen(path_fpending9, "r");
   	char object_fpending9[100];

 	if (file_fpending9 == NULL) {
   	file_fpending9 = fopen(path_fpending9, "w+");
   	fprintf(file_fpending9,"pending9=NULL\n");
   	rewind(file_fpending9);
   	}

   	char path_fpending10[100];
   	sprintf(path_fpending10, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.10", hostname);
   	FILE *file_fpending10;
   	file_fpending10 = fopen(path_fpending10, "r");
   	char object_fpending10[100];

 	if (file_fpending10 == NULL) {
   	file_fpending10 = fopen(path_fpending10, "w+");
   	fprintf(file_fpending10,"pending10=NULL\n");
   	rewind(file_fpending10);
   	}

   	char path_fpending11[100];
   	sprintf(path_fpending11, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.11", hostname);
   	FILE *file_fpending11;
   	file_fpending11 = fopen(path_fpending11, "r");
   	char object_fpending11[100];

 	if (file_fpending11 == NULL) {
   	file_fpending11 = fopen(path_fpending11, "w+");
   	fprintf(file_fpending11,"pending11=NULL\n");
   	rewind(file_fpending11);
   	}

   	char path_fpending12[100];
   	sprintf(path_fpending12, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.12", hostname);
   	FILE *file_fpending12;
   	file_fpending12 = fopen(path_fpending12, "r");
   	char object_fpending12[100];

 	if (file_fpending12 == NULL) {
   	file_fpending12 = fopen(path_fpending12, "w+");
   	fprintf(file_fpending12,"pending12=NULL\n");
   	rewind(file_fpending12);
   	}

   	char path_fpending13[100];
   	sprintf(path_fpending13, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.13", hostname);
   	FILE *file_fpending13;
   	file_fpending13 = fopen(path_fpending13, "r");
   	char object_fpending13[100];

 	if (file_fpending13 == NULL) {
   	file_fpending13 = fopen(path_fpending13, "w+");
   	fprintf(file_fpending13,"pending13=NULL\n");
   	rewind(file_fpending13);
   	}

   	char path_fremote0[100];
   	sprintf(path_fremote0, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.0", hostname);
   	FILE *file_fremote0;
   	file_fremote0 = fopen(path_fremote0, "r");
   	char object_fremote0[100];

 	if (file_fremote0 == NULL) {
   	file_fremote0 = fopen(path_fremote0, "w+");
   	fprintf(file_fremote0,"fremote0=NULL\n");
   	rewind(file_fremote0);
   	}

   	char path_fremote1[100];
   	sprintf(path_fremote1, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.1", hostname);
   	FILE *file_fremote1;
   	file_fremote1 = fopen(path_fremote1, "r");
   	char object_fremote1[100];

 	if (file_fremote1 == NULL) {
   	file_fremote1 = fopen(path_fremote1, "w+");
   	fprintf(file_fremote1,"fremote1=NULL\n");
   	rewind(file_fremote1);
   	}

   	char path_fremote2[100];
   	sprintf(path_fremote2, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.2", hostname);
   	FILE *file_fremote2;
   	file_fremote2 = fopen(path_fremote2, "r");
   	char object_fremote2[100];

 	if (file_fremote2 == NULL) {
   	file_fremote2 = fopen(path_fremote2, "w+");
   	fprintf(file_fremote2,"fremote2=NULL\n");
   	rewind(file_fremote2);
   	}

   	char path_fremote3[100];
   	sprintf(path_fremote3, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.3", hostname);
   	FILE *file_fremote3;
   	file_fremote3 = fopen(path_fremote3, "r");
   	char object_fremote3[100];

 	if (file_fremote3 == NULL) {
   	file_fremote3 = fopen(path_fremote3, "w+");
   	fprintf(file_fremote3,"fremote3=NULL\n");
   	rewind(file_fremote3);
   	}

   	char path_fremote4[100];
   	sprintf(path_fremote4, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.4", hostname);
   	FILE *file_fremote4;
   	file_fremote4 = fopen(path_fremote4, "r");
   	char object_fremote4[100];

 	if (file_fremote4 == NULL) {
   	file_fremote4 = fopen(path_fremote4, "w+");
   	fprintf(file_fremote4,"fremote4=NULL\n");
   	rewind(file_fremote4);
   	}

   	char path_fremote5[100];
   	sprintf(path_fremote5, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.5", hostname);
   	FILE *file_fremote5;
   	file_fremote5 = fopen(path_fremote5, "r");
   	char object_fremote5[100];

 	if (file_fremote5 == NULL) {
   	file_fremote5 = fopen(path_fremote5, "w+");
   	fprintf(file_fremote5,"fremote5=NULL\n");
   	rewind(file_fremote5);
   	}

   	char path_fremote6[100];
   	sprintf(path_fremote6, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.6", hostname);
   	FILE *file_fremote6;
   	file_fremote6 = fopen(path_fremote6, "r");
   	char object_fremote6[100];

 	if (file_fremote6 == NULL) {
   	file_fremote6 = fopen(path_fremote6, "w+");
   	fprintf(file_fremote6,"fremote6=NULL\n");
   	rewind(file_fremote6);
   	}

   	char path_fremote7[100];
   	sprintf(path_fremote7, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.7", hostname);
   	FILE *file_fremote7;
   	file_fremote7 = fopen(path_fremote7, "r");
   	char object_fremote7[100];

 	if (file_fremote7 == NULL) {
   	file_fremote7 = fopen(path_fremote7, "w+");
   	fprintf(file_fremote7,"fremote7=NULL\n");
   	rewind(file_fremote7);
   	}

   	char path_fremote8[100];
   	sprintf(path_fremote8, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.8", hostname);
   	FILE *file_fremote8;
   	file_fremote8 = fopen(path_fremote8, "r");
   	char object_fremote8[100];

 	if (file_fremote8 == NULL) {
   	file_fremote8 = fopen(path_fremote8, "w+");
   	fprintf(file_fremote8,"fremote8=NULL\n");
   	rewind(file_fremote8);
   	}

   	char path_fremote9[100];
   	sprintf(path_fremote9, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.9", hostname);
   	FILE *file_fremote9;
   	file_fremote9 = fopen(path_fremote9, "r");
   	char object_fremote9[100];

 	if (file_fremote9 == NULL) {
   	file_fremote9 = fopen(path_fremote9, "w+");
   	fprintf(file_fremote9,"fremote9=NULL\n");
   	rewind(file_fremote9);
   	}

   	char path_fremote10[100];
   	sprintf(path_fremote10, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.10", hostname);
   	FILE *file_fremote10;
   	file_fremote10 = fopen(path_fremote10, "r");
   	char object_fremote10[100];

 	if (file_fremote10 == NULL) {
   	file_fremote10 = fopen(path_fremote10, "w+");
   	fprintf(file_fremote10,"fremote10=NULL\n");
   	rewind(file_fremote10);
   	}

   	char path_fremote11[100];
   	sprintf(path_fremote11, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.11", hostname);
   	FILE *file_fremote11;
   	file_fremote11 = fopen(path_fremote11, "r");
   	char object_fremote11[100];

 	if (file_fremote11 == NULL) {
   	file_fremote11 = fopen(path_fremote11, "w+");
   	fprintf(file_fremote11,"fremote11=NULL\n");
   	rewind(file_fremote11);
   	}

   	char path_fremote12[100];
   	sprintf(path_fremote12, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.12", hostname);
   	FILE *file_fremote12;
   	file_fremote12 = fopen(path_fremote12, "r");
   	char object_fremote12[100];

 	if (file_fremote12 == NULL) {
   	file_fremote12 = fopen(path_fremote12, "w+");
   	fprintf(file_fremote12,"fremote12=NULL\n");
   	rewind(file_fremote12);
   	}

   	char path_fremote13[100];
   	sprintf(path_fremote13, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.13", hostname);
   	FILE *file_fremote13;
   	file_fremote13 = fopen(path_fremote13, "r");
   	char object_fremote13[100];

 	if (file_fremote13 == NULL) {
   	file_fremote13 = fopen(path_fremote13, "w+");
   	fprintf(file_fremote13,"fremote13=NULL\n");
   	rewind(file_fremote13);
   	}

   	char path_fhostname0[100];
   	sprintf(path_fhostname0, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.0", hostname);
  	FILE *file_fhostname0;
	file_fhostname0 = fopen(path_fhostname0, "r");
   	char object_fhostname0[100];

 	if (file_fhostname0 == NULL) {
   	file_fhostname0 = fopen(path_fhostname0, "w+");
   	fprintf(file_fhostname0,"hostname0=NULL\n");
   	rewind(file_fhostname0);
   	}

   	char path_fhostname1[100];
   	sprintf(path_fhostname1, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.1", hostname);
   	FILE *file_fhostname1;
   	file_fhostname1 = fopen(path_fhostname1, "r");
   	char object_fhostname1[100];

 	if (file_fhostname1 == NULL) {
   	file_fhostname1 = fopen(path_fhostname1, "w+");
   	fprintf(file_fhostname1,"hostname1=NULL\n");
   	rewind(file_fhostname1);
   	}

   	char path_fhostname2[100];
   	sprintf(path_fhostname2, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.2", hostname);
   	FILE *file_fhostname2;
   	file_fhostname2 = fopen(path_fhostname2, "r");
   	char object_fhostname2[100];

 	if (file_fhostname2 == NULL) {
   	file_fhostname2 = fopen(path_fhostname2, "w+");
   	fprintf(file_fhostname2,"hostname2=NULL\n");
   	rewind(file_fhostname2);
   	}

   	char path_fhostname3[100];
   	sprintf(path_fhostname3, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.3", hostname);
   	FILE *file_fhostname3;
   	file_fhostname3 = fopen(path_fhostname3, "r");
   	char object_fhostname3[100];

 	if (file_fhostname3 == NULL) {
   	file_fhostname3 = fopen(path_fhostname3, "w+");
   	fprintf(file_fhostname3,"hostname3=NULL\n");
   	rewind(file_fhostname3);
   	}

   	char path_fhostname4[100];
   	sprintf(path_fhostname4, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.4", hostname);
   	FILE *file_fhostname4;
   	file_fhostname4 = fopen(path_fhostname4, "r");
   	char object_fhostname4[100];

 	if (file_fhostname4 == NULL) {
   	file_fhostname4 = fopen(path_fhostname4, "w+");
   	fprintf(file_fhostname4,"hostname4=NULL\n");
   	rewind(file_fhostname4);
   	}

   	char path_fhostname5[100];
   	sprintf(path_fhostname5, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.5", hostname);
   	FILE *file_fhostname5;
   	file_fhostname5 = fopen(path_fhostname5, "r");
   	char object_fhostname5[100];

 	if (file_fhostname5 == NULL) {
   	file_fhostname5 = fopen(path_fhostname5, "w+");
   	fprintf(file_fhostname5,"hostname5=NULL\n");
   	rewind(file_fhostname5);
   	}

   	char path_fhostname6[100];
   	sprintf(path_fhostname6, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.6", hostname);
   	FILE *file_fhostname6;
   	file_fhostname6 = fopen(path_fhostname6, "r");
   	char object_fhostname6[100];

 	if (file_fhostname6 == NULL) {
   	file_fhostname6 = fopen(path_fhostname6, "w+");
   	fprintf(file_fhostname6,"hostname6=NULL\n");
   	rewind(file_fhostname6);
   	}

   	char path_fhostname7[100];
   	sprintf(path_fhostname7, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.7", hostname);
   	FILE *file_fhostname7;
   	file_fhostname7 = fopen(path_fhostname7, "r");
   	char object_fhostname7[100];

 	if (file_fhostname7 == NULL) {
   	file_fhostname7 = fopen(path_fhostname7, "w+");
   	fprintf(file_fhostname7,"hostname7=NULL\n");
   	rewind(file_fhostname7);
   	}

   	char path_fhostname8[100];
   	sprintf(path_fhostname8, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.8", hostname);
   	FILE *file_fhostname8;
   	file_fhostname8 = fopen(path_fhostname8, "r");
   	char object_fhostname8[100];

 	if (file_fhostname8 == NULL) {
   	file_fhostname8 = fopen(path_fhostname8, "w+");
   	fprintf(file_fhostname8,"hostname8=NULL\n");
   	rewind(file_fhostname8);
   	}

   	char path_fhostname9[100];
   	sprintf(path_fhostname9, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.9", hostname);
   	FILE *file_fhostname9;
   	file_fhostname9 = fopen(path_fhostname9, "r");
   	char object_fhostname9[100];

 	if (file_fhostname9 == NULL) {
   	file_fhostname9 = fopen(path_fhostname9, "w+");
   	fprintf(file_fhostname9,"hostname9=NULL\n");
   	rewind(file_fhostname9);
   	}

   	char path_fhostname10[100];
   	sprintf(path_fhostname10, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.10", hostname);
   	FILE *file_fhostname10;
   	file_fhostname10 = fopen(path_fhostname10, "r");
   	char object_fhostname10[100];

 	if (file_fhostname10 == NULL) {
   	file_fhostname10 = fopen(path_fhostname10, "w+");
   	fprintf(file_fhostname10,"hostname10=NULL\n");
   	rewind(file_fhostname10);
   	}

   	char path_fhostname11[100];
   	sprintf(path_fhostname11, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.11", hostname);
   	FILE *file_fhostname11;
   	file_fhostname11 = fopen(path_fhostname11, "r");
   	char object_fhostname11[100];

 	if (file_fhostname11 == NULL) {
   	file_fhostname11 = fopen(path_fhostname11, "w+");
   	fprintf(file_fhostname11,"hostname11=NULL\n");
   	rewind(file_fhostname11);
   	}

   	char path_fhostname12[100];
   	sprintf(path_fhostname12, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.12", hostname);
   	FILE *file_fhostname12;
   	file_fhostname12 = fopen(path_fhostname12, "r");
   	char object_fhostname12[100];

 	if (file_fhostname12 == NULL) {
   	file_fhostname12 = fopen(path_fhostname12, "w+");
   	fprintf(file_fhostname12,"hostname12=NULL\n");
   	rewind(file_fhostname12);
   	}

   	char path_fhostname13[100];
   	sprintf(path_fhostname13, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.13", hostname);
   	FILE *file_fhostname13;
   	file_fhostname13 = fopen(path_fhostname13, "r");
   	char object_fhostname13[100];

 	if (file_fhostname13 == NULL) {
   	file_fhostname13 = fopen(path_fhostname13, "w+");
   	fprintf(file_fhostname13,"hostname13=NULL\n");
   	rewind(file_fhostname13);
   	}

   	char path_ftime0[100];
   	sprintf(path_ftime0, "/home/user/ccndStatus-ObjectValues/%s.faces.time.0", hostname);
   	FILE *file_ftime0;
   	file_ftime0 = fopen(path_ftime0, "r");
   	char object_ftime0[100];

 	if (file_ftime0 == NULL) {
   	file_ftime0 = fopen(path_ftime0, "w+");
   	fprintf(file_ftime0,"time0=NULL\n");
   	rewind(file_ftime0);
   	}

   	char path_ftime1[100];
   	sprintf(path_ftime1, "/home/user/ccndStatus-ObjectValues/%s.faces.time.1", hostname);
   	FILE *file_ftime1;
   	file_ftime1 = fopen(path_ftime1, "r");
   	char object_ftime1[100];

 	if (file_ftime1 == NULL) {
   	file_ftime1 = fopen(path_ftime1, "w+");
   	fprintf(file_ftime1,"time1=NULL\n");
   	rewind(file_ftime1);
   	}

   	char path_ftime2[100];
   	sprintf(path_ftime2, "/home/user/ccndStatus-ObjectValues/%s.faces.time.2", hostname);
   	FILE *file_ftime2;
   	file_ftime2 = fopen(path_ftime2, "r");
   	char object_ftime2[100];

 	if (file_ftime2 == NULL) {
   	file_ftime2 = fopen(path_ftime2, "w+");
   	fprintf(file_ftime2,"time2=NULL\n");
   	rewind(file_ftime2);
   	}

   	char path_ftime3[100];
   	sprintf(path_ftime3, "/home/user/ccndStatus-ObjectValues/%s.faces.time.3", hostname);
   	FILE *file_ftime3;
   	file_ftime3 = fopen(path_ftime3, "r");
   	char object_ftime3[100];

 	if (file_ftime3 == NULL) {
   	file_ftime3 = fopen(path_ftime3, "w+");
   	fprintf(file_ftime3,"time3=NULL\n");
   	rewind(file_ftime3);
   	}

   	char path_ftime4[100];
   	sprintf(path_ftime4, "/home/user/ccndStatus-ObjectValues/%s.faces.time.4", hostname);
   	FILE *file_ftime4;
   	file_ftime4 = fopen(path_ftime4, "r");
   	char object_ftime4[100];

 	if (file_ftime4 == NULL) {
   	file_ftime4 = fopen(path_ftime4, "w+");
   	fprintf(file_ftime4,"time4=NULL\n");
   	rewind(file_ftime4);
   	}

   	char path_ftime5[100];
   	sprintf(path_ftime5, "/home/user/ccndStatus-ObjectValues/%s.faces.time.5", hostname);
   	FILE *file_ftime5;
   	file_ftime5 = fopen(path_ftime5, "r");
   	char object_ftime5[100];

 	if (file_ftime5 == NULL) {
   	file_ftime5 = fopen(path_ftime5, "w+");
   	fprintf(file_ftime5,"time5=NULL\n");
   	rewind(file_ftime5);
   	}

   	char path_ftime6[100];
   	sprintf(path_ftime6, "/home/user/ccndStatus-ObjectValues/%s.faces.time.6", hostname);
   	FILE *file_ftime6;
   	file_ftime6 = fopen(path_ftime6, "r");
   	char object_ftime6[100];

 	if (file_ftime6 == NULL) {
   	file_ftime6 = fopen(path_ftime6, "w+");
   	fprintf(file_ftime6,"time6=NULL\n");
   	rewind(file_ftime6);
   	}

   	char path_ftime7[100];
   	sprintf(path_ftime7, "/home/user/ccndStatus-ObjectValues/%s.faces.time.7", hostname);
   	FILE *file_ftime7;
   	file_ftime7 = fopen(path_ftime7, "r");
   	char object_ftime7[100];

 	if (file_ftime7 == NULL) {
   	file_ftime7 = fopen(path_ftime7, "w+");
   	fprintf(file_ftime7,"time7=NULL\n");
   	rewind(file_ftime7);
   	}

   	char path_ftime8[100];
   	sprintf(path_ftime8, "/home/user/ccndStatus-ObjectValues/%s.faces.time.8", hostname);
   	FILE *file_ftime8;
   	file_ftime8 = fopen(path_ftime8, "r");
   	char object_ftime8[100];

 	if (file_ftime8 == NULL) {
   	file_ftime8 = fopen(path_ftime8, "w+");
   	fprintf(file_ftime8,"time8=NULL\n");
   	rewind(file_ftime8);
   	}

   	char path_ftime9[100];
   	sprintf(path_ftime9, "/home/user/ccndStatus-ObjectValues/%s.faces.time.9", hostname);
   	FILE *file_ftime9;
   	file_ftime9 = fopen(path_ftime9, "r");
   	char object_ftime9[100];

 	if (file_ftime9 == NULL) {
   	file_ftime9 = fopen(path_ftime9, "w+");
   	fprintf(file_ftime9,"time9=NULL\n");
   	rewind(file_ftime9);
   	}

   	char path_ftime10[100];
   	sprintf(path_ftime10, "/home/user/ccndStatus-ObjectValues/%s.faces.time.10", hostname);
   	FILE *file_ftime10;
   	file_ftime10 = fopen(path_ftime10, "r");
   	char object_ftime10[100];

 	if (file_ftime10 == NULL) {
   	file_ftime10 = fopen(path_ftime10, "w+");
   	fprintf(file_ftime10,"time10=NULL\n");
   	rewind(file_ftime10);
   	}

   	char path_ftime11[100];
   	sprintf(path_ftime11, "/home/user/ccndStatus-ObjectValues/%s.faces.time.11", hostname);
   	FILE *file_ftime11;
   	file_ftime11 = fopen(path_ftime11, "r");
   	char object_ftime11[100];

 	if (file_ftime11 == NULL) {
   	file_ftime11 = fopen(path_ftime11, "w+");
   	fprintf(file_ftime11,"time11=NULL\n");
   	rewind(file_ftime11);
   	}

   	char path_ftime12[100];
   	sprintf(path_ftime12, "/home/user/ccndStatus-ObjectValues/%s.faces.time.12", hostname);
   	FILE *file_ftime12;
   	file_ftime12 = fopen(path_ftime12, "r");
   	char object_ftime12[100];

 	if (file_ftime12 == NULL) {
   	file_ftime12 = fopen(path_ftime12, "w+");
   	fprintf(file_ftime12,"time12=NULL\n");
   	rewind(file_ftime12);
   	}

   	char path_ftime13[100];
   	sprintf(path_ftime13, "/home/user/ccndStatus-ObjectValues/%s.faces.time.13", hostname);
   	FILE *file_ftime13;
   	file_ftime13 = fopen(path_ftime13, "r");
   	char object_ftime13[100];

 	if (file_ftime13 == NULL) {
   	file_ftime13 = fopen(path_ftime13, "w+");
   	fprintf(file_ftime13,"time13=NULL\n");
   	rewind(file_ftime13);
   	}

//valores de cada objeto de ccndStatus/faces
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE0] = strdup (fgets (object_fface0, sizeof(object_fface0), file_fface0)); fclose(file_fface0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE1] = strdup (fgets (object_fface1, sizeof(object_fface1), file_fface1)); fclose(file_fface1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE2] = strdup (fgets (object_fface2, sizeof(object_fface2), file_fface2)); fclose(file_fface2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE3] = strdup (fgets (object_fface3, sizeof(object_fface3), file_fface3)); fclose(file_fface3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE4] = strdup (fgets (object_fface4, sizeof(object_fface4), file_fface4)); fclose(file_fface4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE5] = strdup (fgets (object_fface5, sizeof(object_fface5), file_fface5)); fclose(file_fface5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE6] = strdup (fgets (object_fface6, sizeof(object_fface6), file_fface6)); fclose(file_fface6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE7] = strdup (fgets (object_fface7, sizeof(object_fface7), file_fface7)); fclose(file_fface7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE8] = strdup (fgets (object_fface8, sizeof(object_fface8), file_fface8)); fclose(file_fface8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE9] = strdup (fgets (object_fface9, sizeof(object_fface9), file_fface9)); fclose(file_fface9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE10] = strdup (fgets (object_fface10, sizeof(object_fface10), file_fface10)); fclose(file_fface10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE11] = strdup (fgets (object_fface11, sizeof(object_fface11), file_fface11)); fclose(file_fface11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE12] = strdup (fgets (object_fface12, sizeof(object_fface12), file_fface12)); fclose(file_fface12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE13] = strdup (fgets (object_fface13, sizeof(object_fface13), file_fface13)); fclose(file_fface13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS0] = strdup (fgets (object_fflags0, sizeof(object_fflags0), file_fflags0)); fclose(file_fflags0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS1] = strdup (fgets (object_fflags1, sizeof(object_fflags1), file_fflags1)); fclose(file_fflags1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS2] = strdup (fgets (object_fflags2, sizeof(object_fflags2), file_fflags2)); fclose(file_fflags2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS3] = strdup (fgets (object_fflags3, sizeof(object_fflags3), file_fflags3)); fclose(file_fflags3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS4] = strdup (fgets (object_fflags4, sizeof(object_fflags4), file_fflags4)); fclose(file_fflags4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS5] = strdup (fgets (object_fflags5, sizeof(object_fflags5), file_fflags5)); fclose(file_fflags5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS6] = strdup (fgets (object_fflags6, sizeof(object_fflags6), file_fflags6)); fclose(file_fflags6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS7] = strdup (fgets (object_fflags7, sizeof(object_fflags7), file_fflags7)); fclose(file_fflags7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS8] = strdup (fgets (object_fflags8, sizeof(object_fflags8), file_fflags8)); fclose(file_fflags8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS9] = strdup (fgets (object_fflags9, sizeof(object_fflags9), file_fflags9)); fclose(file_fflags9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS10] = strdup (fgets (object_fflags10, sizeof(object_fflags10), file_fflags10)); fclose(file_fflags10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS11] = strdup (fgets (object_fflags11, sizeof(object_fflags11), file_fflags11)); fclose(file_fflags11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS12] = strdup (fgets (object_fflags12, sizeof(object_fflags12), file_fflags12)); fclose(file_fflags12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS13] = strdup (fgets (object_fflags13, sizeof(object_fflags13), file_fflags13)); fclose(file_fflags13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL0] = strdup (fgets (object_flocal0, sizeof(object_flocal0), file_flocal0)); fclose(file_flocal0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL1] = strdup (fgets (object_flocal1, sizeof(object_flocal1), file_flocal1)); fclose(file_flocal1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL2] = strdup (fgets (object_flocal2, sizeof(object_flocal2), file_flocal2)); fclose(file_flocal2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL3] = strdup (fgets (object_flocal3, sizeof(object_flocal3), file_flocal3)); fclose(file_flocal3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL4] = strdup (fgets (object_flocal4, sizeof(object_flocal4), file_flocal4)); fclose(file_flocal4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL5] = strdup (fgets (object_flocal5, sizeof(object_flocal5), file_flocal5)); fclose(file_flocal5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL6] = strdup (fgets (object_flocal6, sizeof(object_flocal6), file_flocal6)); fclose(file_flocal6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL7] = strdup (fgets (object_flocal7, sizeof(object_flocal7), file_flocal7)); fclose(file_flocal7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL8] = strdup (fgets (object_flocal8, sizeof(object_flocal8), file_flocal8)); fclose(file_flocal8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL9] = strdup (fgets (object_flocal9, sizeof(object_flocal9), file_flocal9)); fclose(file_flocal9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL10] = strdup (fgets (object_flocal10, sizeof(object_flocal10), file_flocal10)); fclose(file_flocal10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL11] = strdup (fgets (object_flocal11, sizeof(object_flocal11), file_flocal11)); fclose(file_flocal11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL12] = strdup (fgets (object_flocal12, sizeof(object_flocal12), file_flocal12)); fclose(file_flocal12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL13] = strdup (fgets (object_flocal13, sizeof(object_flocal13), file_flocal13)); fclose(file_flocal13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING0] = strdup (fgets (object_fpending0, sizeof(object_fpending0), file_fpending0)); fclose(file_fpending0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING1] = strdup (fgets (object_fpending1, sizeof(object_fpending1), file_fpending1)); fclose(file_fpending1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING2] = strdup (fgets (object_fpending2, sizeof(object_fpending2), file_fpending2)); fclose(file_fpending2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING3] = strdup (fgets (object_fpending3, sizeof(object_fpending3), file_fpending3)); fclose(file_fpending3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING4] = strdup (fgets (object_fpending4, sizeof(object_fpending4), file_fpending4)); fclose(file_fpending4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING5] = strdup (fgets (object_fpending5, sizeof(object_fpending5), file_fpending5)); fclose(file_fpending5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING6] = strdup (fgets (object_fpending6, sizeof(object_fpending6), file_fpending6)); fclose(file_fpending6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING7] = strdup (fgets (object_fpending7, sizeof(object_fpending7), file_fpending7)); fclose(file_fpending7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING8] = strdup (fgets (object_fpending8, sizeof(object_fpending8), file_fpending8)); fclose(file_fpending8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING9] = strdup (fgets (object_fpending9, sizeof(object_fpending9), file_fpending9)); fclose(file_fpending9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING10] = strdup (fgets (object_fpending10, sizeof(object_fpending10), file_fpending10)); fclose(file_fpending10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING11] = strdup (fgets (object_fpending11, sizeof(object_fpending11), file_fpending11)); fclose(file_fpending11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING12] = strdup (fgets (object_fpending12, sizeof(object_fpending12), file_fpending12)); fclose(file_fpending12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING13] = strdup (fgets (object_fpending13, sizeof(object_fpending13), file_fpending13)); fclose(file_fpending13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE0] = strdup (fgets (object_fremote0, sizeof(object_fremote0), file_fremote0)); fclose(file_fremote0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE1] = strdup (fgets (object_fremote1, sizeof(object_fremote1), file_fremote1)); fclose(file_fremote1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE2] = strdup (fgets (object_fremote2, sizeof(object_fremote2), file_fremote2)); fclose(file_fremote2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE3] = strdup (fgets (object_fremote3, sizeof(object_fremote3), file_fremote3)); fclose(file_fremote3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE4] = strdup (fgets (object_fremote4, sizeof(object_fremote4), file_fremote4)); fclose(file_fremote4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE5] = strdup (fgets (object_fremote5, sizeof(object_fremote5), file_fremote5)); fclose(file_fremote5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE6] = strdup (fgets (object_fremote6, sizeof(object_fremote6), file_fremote6)); fclose(file_fremote6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE7] = strdup (fgets (object_fremote7, sizeof(object_fremote7), file_fremote7)); fclose(file_fremote7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE8] = strdup (fgets (object_fremote8, sizeof(object_fremote8), file_fremote8)); fclose(file_fremote8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE9] = strdup (fgets (object_fremote9, sizeof(object_fremote9), file_fremote9)); fclose(file_fremote9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE10] = strdup (fgets (object_fremote10, sizeof(object_fremote10), file_fremote10)); fclose(file_fremote10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE11] = strdup (fgets (object_fremote11, sizeof(object_fremote11), file_fremote11)); fclose(file_fremote11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE12] = strdup (fgets (object_fremote12, sizeof(object_fremote12), file_fremote12)); fclose(file_fremote12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE13] = strdup (fgets (object_fremote13, sizeof(object_fremote13), file_fremote13)); fclose(file_fremote13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST0] = strdup (fgets (object_fhostname0, sizeof(object_fhostname0), file_fhostname0)); fclose(file_fhostname0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST1] = strdup (fgets (object_fhostname1, sizeof(object_fhostname1), file_fhostname1)); fclose(file_fhostname1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST2] = strdup (fgets (object_fhostname2, sizeof(object_fhostname2), file_fhostname2)); fclose(file_fhostname2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST3] = strdup (fgets (object_fhostname3, sizeof(object_fhostname3), file_fhostname3)); fclose(file_fhostname3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST4] = strdup (fgets (object_fhostname4, sizeof(object_fhostname4), file_fhostname4)); fclose(file_fhostname4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST5] = strdup (fgets (object_fhostname5, sizeof(object_fhostname5), file_fhostname5)); fclose(file_fhostname5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST6] = strdup (fgets (object_fhostname6, sizeof(object_fhostname6), file_fhostname6)); fclose(file_fhostname6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST7] = strdup (fgets (object_fhostname7, sizeof(object_fhostname7), file_fhostname7)); fclose(file_fhostname7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST8] = strdup (fgets (object_fhostname8, sizeof(object_fhostname8), file_fhostname8)); fclose(file_fhostname8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST9] = strdup (fgets (object_fhostname9, sizeof(object_fhostname9), file_fhostname9)); fclose(file_fhostname9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST10] = strdup (fgets (object_fhostname10, sizeof(object_fhostname10), file_fhostname10)); fclose(file_fhostname10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST11] = strdup (fgets (object_fhostname11, sizeof(object_fhostname11), file_fhostname11)); fclose(file_fhostname11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST12] = strdup (fgets (object_fhostname12, sizeof(object_fhostname12), file_fhostname12)); fclose(file_fhostname12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST13] = strdup (fgets (object_fhostname13, sizeof(object_fhostname13), file_fhostname13)); fclose(file_fhostname13);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP0] = strdup (fgets (object_ftime0, sizeof(object_ftime0), file_ftime0)); fclose(file_ftime0);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP1] = strdup (fgets (object_ftime1, sizeof(object_ftime1), file_ftime1)); fclose(file_ftime1);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP2] = strdup (fgets (object_ftime2, sizeof(object_ftime2), file_ftime2)); fclose(file_ftime2);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP3] = strdup (fgets (object_ftime3, sizeof(object_ftime3), file_ftime3)); fclose(file_ftime3);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP4] = strdup (fgets (object_ftime4, sizeof(object_ftime4), file_ftime4)); fclose(file_ftime4);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP5] = strdup (fgets (object_ftime5, sizeof(object_ftime5), file_ftime5)); fclose(file_ftime5);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP6] = strdup (fgets (object_ftime6, sizeof(object_ftime6), file_ftime6)); fclose(file_ftime6);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP7] = strdup (fgets (object_ftime7, sizeof(object_ftime7), file_ftime7)); fclose(file_ftime7);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP8] = strdup (fgets (object_ftime8, sizeof(object_ftime8), file_ftime8)); fclose(file_ftime8);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP9] = strdup (fgets (object_ftime9, sizeof(object_ftime9), file_ftime9)); fclose(file_ftime9);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP10] = strdup (fgets (object_ftime10, sizeof(object_ftime10), file_ftime10)); fclose(file_ftime10);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP11] = strdup (fgets (object_ftime11, sizeof(object_ftime11), file_ftime11)); fclose(file_ftime11);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP12] = strdup (fgets (object_ftime12, sizeof(object_ftime12), file_ftime12)); fclose(file_ftime12);
   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP13] = strdup (fgets (object_ftime13, sizeof(object_ftime13), file_ftime13)); fclose(file_ftime13);


//leitura de arquivos com conteudo de cada objeto de ccndStatus/faceActivityRates

   	char path_farface0[100];
   	sprintf(path_farface0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.0", hostname);
   	FILE *file_farface0;
   	file_farface0 = fopen(path_farface0, "r");
   	char object_farface0[100];

 	if (file_farface0 == NULL) {
   	file_farface0 = fopen(path_farface0, "w+");
   	fprintf(file_farface0,"face0=NULL\n");
   	rewind(file_farface0);
   	}

   	char path_farface1[100];
   	sprintf(path_farface1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.1", hostname);
   	FILE *file_farface1;
   	file_farface1 = fopen(path_farface1, "r");
   	char object_farface1[100];

 	if (file_farface1 == NULL) {
   	file_farface1 = fopen(path_farface1, "w+");
   	fprintf(file_farface1,"face1=NULL\n");
   	rewind(file_farface1);
   	}

	char path_farface2[100];
   	sprintf(path_farface2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.2", hostname);
   	FILE *file_farface2;
   	file_farface2 = fopen(path_farface2, "r");
   	char object_farface2[100];

 	if (file_farface2 == NULL) {
   	file_farface2 = fopen(path_farface2, "w+");
   	fprintf(file_farface2,"face2=NULL\n");
   	rewind(file_farface2);
   	}

	char path_farface3[100];
   	sprintf(path_farface3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.3", hostname);
   	FILE *file_farface3;
   	file_farface3 = fopen(path_farface3, "r");
   	char object_farface3[100];

 	if (file_farface3 == NULL) {
   	file_farface3 = fopen(path_farface3, "w+");
   	fprintf(file_farface3,"face3=NULL\n");
   	rewind(file_farface3);
   	}

	char path_farface4[100];
   	sprintf(path_farface4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.4", hostname);
   	FILE *file_farface4;
   	file_farface4 = fopen(path_farface4, "r");
   	char object_farface4[100];

 	if (file_farface4 == NULL) {
   	file_farface4 = fopen(path_farface4, "w+");
   	fprintf(file_farface4,"face4=NULL\n");
   	rewind(file_farface4);
   	}

	char path_farface5[100];
   	sprintf(path_farface5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.5", hostname);
   	FILE *file_farface5;
   	file_farface5 = fopen(path_farface5, "r");
   	char object_farface5[100];

 	if (file_farface5 == NULL) {
   	file_farface5 = fopen(path_farface5, "w+");
   	fprintf(file_farface5,"face5=NULL\n");
   	rewind(file_farface5);
   	}

	char path_farface6[100];
   	sprintf(path_farface6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.6", hostname);
   	FILE *file_farface6;
   	file_farface6 = fopen(path_farface6, "r");
   	char object_farface6[100];

 	if (file_farface6 == NULL) {
   	file_farface6 = fopen(path_farface6, "w+");
   	fprintf(file_farface6,"face6=NULL\n");
   	rewind(file_farface6);
   	}

	char path_farface7[100];
   	sprintf(path_farface7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.7", hostname);
   	FILE *file_farface7;
   	file_farface7 = fopen(path_farface7, "r");
   	char object_farface7[100];

 	if (file_farface7 == NULL) {
   	file_farface7 = fopen(path_farface7, "w+");
   	fprintf(file_farface7,"face7=NULL\n");
   	rewind(file_farface7);
   	}

	char path_farface8[100];
   	sprintf(path_farface8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.8", hostname);
   	FILE *file_farface8;
   	file_farface8 = fopen(path_farface8, "r");
   	char object_farface8[100];

 	if (file_farface8 == NULL) {
   	file_farface8 = fopen(path_farface8, "w+");
   	fprintf(file_farface8,"face8=NULL\n");
   	rewind(file_farface8);
   	}

   	char path_farBIn0[100];
   	sprintf(path_farBIn0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.0", hostname);
   	FILE *file_farBIn0;
   	file_farBIn0 = fopen(path_farBIn0, "r");
   	char object_farBIn0[100];

 	if (file_farBIn0 == NULL) {
   	file_farBIn0 = fopen(path_farBIn0, "w+");
   	fprintf(file_farBIn0,"BIn0=NULL\n");
   	rewind(file_farBIn0);
   	}

 	char path_farBIn1[100];
   	sprintf(path_farBIn1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.1", hostname);
   	FILE *file_farBIn1;
   	file_farBIn1 = fopen(path_farBIn1, "r");
   	char object_farBIn1[100];

 	if (file_farBIn1 == NULL) {
   	file_farBIn1 = fopen(path_farBIn1, "w+");
   	fprintf(file_farBIn1,"BIn1=NULL\n");
   	rewind(file_farBIn1);
   	}

 	char path_farBIn2[100];
   	sprintf(path_farBIn2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.2", hostname);
   	FILE *file_farBIn2;
   	file_farBIn2 = fopen(path_farBIn2, "r");
   	char object_farBIn2[100];

 	if (file_farBIn2 == NULL) {
   	file_farBIn2 = fopen(path_farBIn2, "w+");
   	fprintf(file_farBIn2,"BIn2=NULL\n");
   	rewind(file_farBIn2);
   	}

 	char path_farBIn3[100];
   	sprintf(path_farBIn3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.3", hostname);
   	FILE *file_farBIn3;
   	file_farBIn3 = fopen(path_farBIn3, "r");
   	char object_farBIn3[100];

 	if (file_farBIn3 == NULL) {
   	file_farBIn3 = fopen(path_farBIn3, "w+");
   	fprintf(file_farBIn3,"BIn3=NULL\n");
   	rewind(file_farBIn3);
   	}

 	char path_farBIn4[100];
   	sprintf(path_farBIn4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.4", hostname);
   	FILE *file_farBIn4;
   	file_farBIn4 = fopen(path_farBIn4, "r");
   	char object_farBIn4[100];

 	if (file_farBIn4 == NULL) {
   	file_farBIn4 = fopen(path_farBIn4, "w+");
   	fprintf(file_farBIn4,"BIn4=NULL\n");
   	rewind(file_farBIn4);
   	}

 	char path_farBIn5[100];
   	sprintf(path_farBIn5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.5", hostname);
   	FILE *file_farBIn5;
   	file_farBIn5 = fopen(path_farBIn5, "r");
   	char object_farBIn5[100];

 	if (file_farBIn5 == NULL) {
   	file_farBIn5 = fopen(path_farBIn5, "w+");
   	fprintf(file_farBIn5,"BIn5=NULL\n");
   	rewind(file_farBIn5);
   	}

 	char path_farBIn6[100];
   	sprintf(path_farBIn6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.6", hostname);
   	FILE *file_farBIn6;
   	file_farBIn6 = fopen(path_farBIn6, "r");
   	char object_farBIn6[100];

 	if (file_farBIn6 == NULL) {
   	file_farBIn6 = fopen(path_farBIn6, "w+");
   	fprintf(file_farBIn6,"BIn6=NULL\n");
   	rewind(file_farBIn6);
   	}

 	char path_farBIn7[100];
   	sprintf(path_farBIn7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.7", hostname);
   	FILE *file_farBIn7;
   	file_farBIn7 = fopen(path_farBIn7, "r");
   	char object_farBIn7[100];

 	if (file_farBIn7 == NULL) {
   	file_farBIn7 = fopen(path_farBIn7, "w+");
   	fprintf(file_farBIn7,"BIn7=NULL\n");
   	rewind(file_farBIn7);
   	}

 	char path_farBIn8[100];
   	sprintf(path_farBIn8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.8", hostname);
   	FILE *file_farBIn8;
   	file_farBIn8 = fopen(path_farBIn8, "r");
   	char object_farBIn8[100];

 	if (file_farBIn8 == NULL) {
   	file_farBIn8 = fopen(path_farBIn8, "w+");
   	fprintf(file_farBIn8,"BIn8=NULL\n");
   	rewind(file_farBIn8);
   	}

   	char path_farBOut0[100];
   	sprintf(path_farBOut0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.0", hostname);
   	FILE *file_farBOut0;
   	file_farBOut0 = fopen(path_farBOut0, "r");
	char object_farBOut0[100];

 	if (file_farBOut0 == NULL) {
   	file_farBOut0 = fopen(path_farBOut0, "w+");
   	fprintf(file_farBOut0,"BOut0=NULL\n");
   	rewind(file_farBOut0);
   	}

   	char path_farBOut1[100];
   	sprintf(path_farBOut1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.1", hostname);
   	FILE *file_farBOut1;
   	file_farBOut1 = fopen(path_farBOut1, "r");
	char object_farBOut1[100];

 	if (file_farBOut1 == NULL) {
   	file_farBOut1 = fopen(path_farBOut1, "w+");
   	fprintf(file_farBOut1,"BOut1=NULL\n");
   	rewind(file_farBOut1);
   	}

   	char path_farBOut2[100];
   	sprintf(path_farBOut2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.2", hostname);
   	FILE *file_farBOut2;
   	file_farBOut2 = fopen(path_farBOut2, "r");
	char object_farBOut2[100];

 	if (file_farBOut2 == NULL) {
   	file_farBOut2 = fopen(path_farBOut2, "w+");
   	fprintf(file_farBOut2,"BOut2=NULL\n");
   	rewind(file_farBOut2);
   	}

   	char path_farBOut3[100];
   	sprintf(path_farBOut3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.3", hostname);
   	FILE *file_farBOut3;
   	file_farBOut3 = fopen(path_farBOut3, "r");
	char object_farBOut3[100];

 	if (file_farBOut3 == NULL) {
   	file_farBOut3 = fopen(path_farBOut3, "w+");
   	fprintf(file_farBOut3,"BOut3=NULL\n");
   	rewind(file_farBOut3);
   	}

   	char path_farBOut4[100];
   	sprintf(path_farBOut4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.4", hostname);
   	FILE *file_farBOut4;
   	file_farBOut4 = fopen(path_farBOut4, "r");
	char object_farBOut4[100];

 	if (file_farBOut4 == NULL) {
   	file_farBOut4 = fopen(path_farBOut4, "w+");
   	fprintf(file_farBOut4,"BOut4=NULL\n");
   	rewind(file_farBOut4);
   	}

   	char path_farBOut5[100];
   	sprintf(path_farBOut5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.5", hostname);
   	FILE *file_farBOut5;
   	file_farBOut5 = fopen(path_farBOut5, "r");
	char object_farBOut5[100];

 	if (file_farBOut5 == NULL) {
   	file_farBOut5 = fopen(path_farBOut5, "w+");
   	fprintf(file_farBOut5,"BOut5=NULL\n");
   	rewind(file_farBOut5);
   	}

   	char path_farBOut6[100];
   	sprintf(path_farBOut6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.6", hostname);
   	FILE *file_farBOut6;
   	file_farBOut6 = fopen(path_farBOut6, "r");
	char object_farBOut6[100];

 	if (file_farBOut6 == NULL) {
   	file_farBOut6 = fopen(path_farBOut6, "w+");
   	fprintf(file_farBOut6,"BOut6=NULL\n");
   	rewind(file_farBOut6);
   	}

   	char path_farBOut7[100];
   	sprintf(path_farBOut7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.7", hostname);
   	FILE *file_farBOut7;
   	file_farBOut7 = fopen(path_farBOut7, "r");
	char object_farBOut7[100];

 	if (file_farBOut7 == NULL) {
   	file_farBOut7 = fopen(path_farBOut7, "w+");
   	fprintf(file_farBOut7,"BOut7=NULL\n");
   	rewind(file_farBOut7);
   	}

   	char path_farBOut8[100];
   	sprintf(path_farBOut8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.8", hostname);
   	FILE *file_farBOut8;
   	file_farBOut8 = fopen(path_farBOut8, "r");
	char object_farBOut8[100];

 	if (file_farBOut8 == NULL) {
   	file_farBOut8 = fopen(path_farBOut8, "w+");
   	fprintf(file_farBOut8,"BOut8=NULL\n");
   	rewind(file_farBOut8);
   	}

  	char path_farrData0[100];
  	sprintf(path_farrData0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.0", hostname);
   	FILE *file_farrData0;
   	file_farrData0 = fopen(path_farrData0, "r");
   	char object_farrData0[100];

 	if (file_farrData0 == NULL) {
   	file_farrData0 = fopen(path_farrData0, "w+");
   	fprintf(file_farrData0,"rData0=NULL\n");
   	rewind(file_farrData0);
   	}

  	char path_farrData1[100];
  	sprintf(path_farrData1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.1", hostname);
   	FILE *file_farrData1;
   	file_farrData1 = fopen(path_farrData1, "r");
   	char object_farrData1[100];

 	if (file_farrData1 == NULL) {
   	file_farrData1 = fopen(path_farrData1, "w+");
   	fprintf(file_farrData1,"rData1=NULL\n");
   	rewind(file_farrData1);
   	}

  	char path_farrData2[100];
  	sprintf(path_farrData2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.2", hostname);
   	FILE *file_farrData2;
   	file_farrData2 = fopen(path_farrData2, "r");
   	char object_farrData2[100];

 	if (file_farrData2 == NULL) {
   	file_farrData2 = fopen(path_farrData2, "w+");
   	fprintf(file_farrData2,"rData2=NULL\n");
   	rewind(file_farrData2);
   	}

  	char path_farrData3[100];
  	sprintf(path_farrData3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.3", hostname);
   	FILE *file_farrData3;
   	file_farrData3 = fopen(path_farrData3, "r");
   	char object_farrData3[100];

 	if (file_farrData3 == NULL) {
   	file_farrData3 = fopen(path_farrData3, "w+");
   	fprintf(file_farrData3,"rData3=NULL\n");
   	rewind(file_farrData3);
   	}

  	char path_farrData4[100];
  	sprintf(path_farrData4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.4", hostname);
   	FILE *file_farrData4;
   	file_farrData4 = fopen(path_farrData4, "r");
   	char object_farrData4[100];

 	if (file_farrData4 == NULL) {
   	file_farrData4 = fopen(path_farrData4, "w+");
   	fprintf(file_farrData4,"rData4=NULL\n");
   	rewind(file_farrData4);
   	}

  	char path_farrData5[100];
  	sprintf(path_farrData5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.5", hostname);
   	FILE *file_farrData5;
   	file_farrData5 = fopen(path_farrData5, "r");
   	char object_farrData5[100];

 	if (file_farrData5 == NULL) {
   	file_farrData5 = fopen(path_farrData5, "w+");
   	fprintf(file_farrData5,"rData5=NULL\n");
   	rewind(file_farrData5);
   	}

  	char path_farrData6[100];
  	sprintf(path_farrData6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.6", hostname);
   	FILE *file_farrData6;
   	file_farrData6 = fopen(path_farrData6, "r");
   	char object_farrData6[100];

 	if (file_farrData6 == NULL) {
   	file_farrData6 = fopen(path_farrData6, "w+");
   	fprintf(file_farrData6,"rData6=NULL\n");
   	rewind(file_farrData6);
   	}

  	char path_farrData7[100];
  	sprintf(path_farrData7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.7", hostname);
   	FILE *file_farrData7;
   	file_farrData7 = fopen(path_farrData7, "r");
   	char object_farrData7[100];

 	if (file_farrData7 == NULL) {
   	file_farrData7 = fopen(path_farrData7, "w+");
   	fprintf(file_farrData7,"rData7=NULL\n");
   	rewind(file_farrData7);
   	}

  	char path_farrData8[100];
  	sprintf(path_farrData8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.8", hostname);
   	FILE *file_farrData8;
   	file_farrData8 = fopen(path_farrData8, "r");
   	char object_farrData8[100];

 	if (file_farrData8 == NULL) {
   	file_farrData8 = fopen(path_farrData8, "w+");
   	fprintf(file_farrData8,"rData8=NULL\n");
   	rewind(file_farrData8);
   	}

   	char path_farsData0[100];
   	sprintf(path_farsData0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.0", hostname);
   	FILE *file_farsData0;
   	file_farsData0 = fopen(path_farsData0, "r");
   	char object_farsData0[100];

 	if (file_farsData0 == NULL) {
   	file_farsData0 = fopen(path_farsData0, "w+");
   	fprintf(file_farsData0,"sData0=NULL\n");
   	rewind(file_farsData0);
   	}

   	char path_farsData1[100];
   	sprintf(path_farsData1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.1", hostname);
   	FILE *file_farsData1;
   	file_farsData1 = fopen(path_farsData1, "r");
   	char object_farsData1[100];

 	if (file_farsData1 == NULL) {
   	file_farsData1 = fopen(path_farsData1, "w+");
   	fprintf(file_farsData1,"sData1=NULL\n");
   	rewind(file_farsData1);
   	}

   	char path_farsData2[100];
   	sprintf(path_farsData2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.2", hostname);
   	FILE *file_farsData2;
   	file_farsData2 = fopen(path_farsData2, "r");
   	char object_farsData2[100];

 	if (file_farsData2 == NULL) {
   	file_farsData2 = fopen(path_farsData2, "w+");
   	fprintf(file_farsData2,"sData2=NULL\n");
   	rewind(file_farsData2);
   	}

   	char path_farsData3[100];
   	sprintf(path_farsData3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.3", hostname);
   	FILE *file_farsData3;
   	file_farsData3 = fopen(path_farsData3, "r");
   	char object_farsData3[100];

 	if (file_farsData3 == NULL) {
   	file_farsData3 = fopen(path_farsData3, "w+");
   	fprintf(file_farsData3,"sData3=NULL\n");
   	rewind(file_farsData3);
   	}

   	char path_farsData4[100];
   	sprintf(path_farsData4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.4", hostname);
   	FILE *file_farsData4;
   	file_farsData4 = fopen(path_farsData4, "r");
   	char object_farsData4[100];

 	if (file_farsData4 == NULL) {
   	file_farsData4 = fopen(path_farsData4, "w+");
   	fprintf(file_farsData4,"sData4=NULL\n");
   	rewind(file_farsData4);
   	}

   	char path_farsData5[100];
   	sprintf(path_farsData5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.5", hostname);
   	FILE *file_farsData5;
   	file_farsData5 = fopen(path_farsData5, "r");
   	char object_farsData5[100];

 	if (file_farsData5 == NULL) {
   	file_farsData5 = fopen(path_farsData5, "w+");
   	fprintf(file_farsData5,"sData5=NULL\n");
   	rewind(file_farsData5);
   	}

   	char path_farsData6[100];
   	sprintf(path_farsData6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.6", hostname);
   	FILE *file_farsData6;
   	file_farsData6 = fopen(path_farsData6, "r");
   	char object_farsData6[100];

 	if (file_farsData6 == NULL) {
   	file_farsData6 = fopen(path_farsData6, "w+");
   	fprintf(file_farsData6,"sData6=NULL\n");
   	rewind(file_farsData6);
   	}

   	char path_farsData7[100];
   	sprintf(path_farsData7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.7", hostname);
   	FILE *file_farsData7;
   	file_farsData7 = fopen(path_farsData7, "r");
   	char object_farsData7[100];

 	if (file_farsData7 == NULL) {
   	file_farsData7 = fopen(path_farsData7, "w+");
   	fprintf(file_farsData7,"sData7=NULL\n");
   	rewind(file_farsData7);
   	}

   	char path_farsData8[100];
   	sprintf(path_farsData8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.8", hostname);
   	FILE *file_farsData8;
   	file_farsData8 = fopen(path_farsData8, "r");
   	char object_farsData8[100];

 	if (file_farsData8 == NULL) {
   	file_farsData8 = fopen(path_farsData8, "w+");
   	fprintf(file_farsData8,"sData8=NULL\n");
   	rewind(file_farsData8);
   	}

	char path_farrInt0[100];
   	sprintf(path_farrInt0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.0", hostname);
   	FILE *file_farrInt0;
   	file_farrInt0 = fopen(path_farrInt0, "r");
   	char object_farrInt0[100];

 	if (file_farrInt0 == NULL) {
   	file_farrInt0 = fopen(path_farrInt0, "w+");
   	fprintf(file_farrInt0,"rInt0=NULL\n");
   	rewind(file_farrInt0);
   	}

	char path_farrInt1[100];
   	sprintf(path_farrInt1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.1", hostname);
   	FILE *file_farrInt1;
   	file_farrInt1 = fopen(path_farrInt1, "r");
   	char object_farrInt1[100];

 	if (file_farrInt1 == NULL) {
   	file_farrInt1 = fopen(path_farrInt1, "w+");
   	fprintf(file_farrInt1,"rInt1=NULL\n");
   	rewind(file_farrInt1);
   	}

	char path_farrInt2[100];
   	sprintf(path_farrInt2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.2", hostname);
   	FILE *file_farrInt2;
   	file_farrInt2 = fopen(path_farrInt2, "r");
   	char object_farrInt2[100];

 	if (file_farrInt2 == NULL) {
   	file_farrInt2 = fopen(path_farrInt2, "w+");
   	fprintf(file_farrInt2,"rInt2=NULL\n");
   	rewind(file_farrInt2);
   	}

	char path_farrInt3[100];
   	sprintf(path_farrInt3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.3", hostname);
   	FILE *file_farrInt3;
   	file_farrInt3 = fopen(path_farrInt3, "r");
   	char object_farrInt3[100];

 	if (file_farrInt3 == NULL) {
   	file_farrInt3 = fopen(path_farrInt3, "w+");
   	fprintf(file_farrInt3,"rInt3=NULL\n");
   	rewind(file_farrInt3);
   	}

	char path_farrInt4[100];
   	sprintf(path_farrInt4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.4", hostname);
   	FILE *file_farrInt4;
   	file_farrInt4 = fopen(path_farrInt4, "r");
   	char object_farrInt4[100];

 	if (file_farrInt4 == NULL) {
   	file_farrInt4 = fopen(path_farrInt4, "w+");
   	fprintf(file_farrInt4,"rInt4=NULL\n");
   	rewind(file_farrInt4);
   	}

	char path_farrInt5[100];
   	sprintf(path_farrInt5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.5", hostname);
   	FILE *file_farrInt5;
   	file_farrInt5 = fopen(path_farrInt5, "r");
   	char object_farrInt5[100];

 	if (file_farrInt5 == NULL) {
   	file_farrInt5 = fopen(path_farrInt5, "w+");
   	fprintf(file_farrInt5,"rInt5=NULL\n");
   	rewind(file_farrInt5);
   	}

	char path_farrInt6[100];
   	sprintf(path_farrInt6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.6", hostname);
   	FILE *file_farrInt6;
   	file_farrInt6 = fopen(path_farrInt6, "r");
   	char object_farrInt6[100];

 	if (file_farrInt6 == NULL) {
   	file_farrInt6 = fopen(path_farrInt6, "w+");
   	fprintf(file_farrInt6,"rInt6=NULL\n");
   	rewind(file_farrInt6);
   	}

	char path_farrInt7[100];
   	sprintf(path_farrInt7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.7", hostname);
   	FILE *file_farrInt7;
   	file_farrInt7 = fopen(path_farrInt7, "r");
   	char object_farrInt7[100];

 	if (file_farrInt7 == NULL) {
   	file_farrInt7 = fopen(path_farrInt7, "w+");
   	fprintf(file_farrInt7,"rInt7=NULL\n");
   	rewind(file_farrInt7);
   	}

	char path_farrInt8[100];
   	sprintf(path_farrInt8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.8", hostname);
   	FILE *file_farrInt8;
   	file_farrInt8 = fopen(path_farrInt8, "r");
   	char object_farrInt8[100];

 	if (file_farrInt8 == NULL) {
   	file_farrInt8 = fopen(path_farrInt8, "w+");
   	fprintf(file_farrInt8,"rInt8=NULL\n");
   	rewind(file_farrInt8);
   	}

	char path_farsInt0[100];
   	sprintf(path_farsInt0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.0", hostname);
   	FILE *file_farsInt0;
   	file_farsInt0 = fopen(path_farsInt0, "r");
   	char object_farsInt0[100];

 	if (file_farsInt0 == NULL) {
   	file_farsInt0 = fopen(path_farsInt0, "w+");
   	fprintf(file_farsInt0,"sInt0=NULL\n");
   	rewind(file_farsInt0);
   	}

	char path_farsInt1[100];
   	sprintf(path_farsInt1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.1", hostname);
   	FILE *file_farsInt1;
   	file_farsInt1 = fopen(path_farsInt1, "r");
   	char object_farsInt1[100];

 	if (file_farsInt1 == NULL) {
   	file_farsInt1 = fopen(path_farsInt1, "w+");
   	fprintf(file_farsInt1,"sInt1=NULL\n");
   	rewind(file_farsInt1);
   	}

	char path_farsInt2[100];
   	sprintf(path_farsInt2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.2", hostname);
   	FILE *file_farsInt2;
   	file_farsInt2 = fopen(path_farsInt2, "r");
   	char object_farsInt2[100];

 	if (file_farsInt2 == NULL) {
   	file_farsInt2 = fopen(path_farsInt2, "w+");
   	fprintf(file_farsInt2,"sInt2=NULL\n");
   	rewind(file_farsInt2);
   	}

	char path_farsInt3[100];
   	sprintf(path_farsInt3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.3", hostname);
   	FILE *file_farsInt3;
   	file_farsInt3 = fopen(path_farsInt3, "r");
   	char object_farsInt3[100];

 	if (file_farsInt3 == NULL) {
   	file_farsInt3 = fopen(path_farsInt3, "w+");
   	fprintf(file_farsInt3,"sInt3=NULL\n");
   	rewind(file_farsInt3);
   	}

	char path_farsInt4[100];
   	sprintf(path_farsInt4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.4", hostname);
   	FILE *file_farsInt4;
   	file_farsInt4 = fopen(path_farsInt4, "r");
   	char object_farsInt4[100];

 	if (file_farsInt4 == NULL) {
   	file_farsInt4 = fopen(path_farsInt4, "w+");
   	fprintf(file_farsInt4,"sInt4=NULL\n");
   	rewind(file_farsInt4);
   	}

	char path_farsInt5[100];
   	sprintf(path_farsInt5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.5", hostname);
   	FILE *file_farsInt5;
   	file_farsInt5 = fopen(path_farsInt5, "r");
   	char object_farsInt5[100];

 	if (file_farsInt5 == NULL) {
   	file_farsInt5 = fopen(path_farsInt5, "w+");
   	fprintf(file_farsInt5,"sInt5=NULL\n");
   	rewind(file_farsInt5);
   	}

	char path_farsInt6[100];
   	sprintf(path_farsInt6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.6", hostname);
   	FILE *file_farsInt6;
   	file_farsInt6 = fopen(path_farsInt6, "r");
   	char object_farsInt6[100];

 	if (file_farsInt6 == NULL) {
   	file_farsInt6 = fopen(path_farsInt6, "w+");
   	fprintf(file_farsInt6,"sInt6=NULL\n");
   	rewind(file_farsInt6);
   	}

	char path_farsInt7[100];
   	sprintf(path_farsInt7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.7", hostname);
   	FILE *file_farsInt7;
   	file_farsInt7 = fopen(path_farsInt7, "r");
   	char object_farsInt7[100];

 	if (file_farsInt7 == NULL) {
   	file_farsInt7 = fopen(path_farsInt7, "w+");
   	fprintf(file_farsInt7,"sInt7=NULL\n");
   	rewind(file_farsInt7);
   	}

	char path_farsInt8[100];
   	sprintf(path_farsInt8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.8", hostname);
   	FILE *file_farsInt8;
   	file_farsInt8 = fopen(path_farsInt8, "r");
   	char object_farsInt8[100];

 	if (file_farsInt8 == NULL) {
   	file_farsInt8 = fopen(path_farsInt8, "w+");
   	fprintf(file_farsInt8,"sInt8=NULL\n");
   	rewind(file_farsInt8);
   	}

   	char path_farhostname0[100];
   	sprintf(path_farhostname0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.0", hostname);
  	FILE *file_farhostname0;
	file_farhostname0 = fopen(path_farhostname0, "r");
   	char object_farhostname0[100];

 	if (file_farhostname0 == NULL) {
   	file_farhostname0 = fopen(path_farhostname0, "w+");
   	fprintf(file_farhostname0,"hostname0=NULL\n");
   	rewind(file_farhostname0);
   	}

   	char path_farhostname1[100];
   	sprintf(path_farhostname1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.1", hostname);
  	FILE *file_farhostname1;
	file_farhostname1 = fopen(path_farhostname1, "r");
   	char object_farhostname1[100];

 	if (file_farhostname1 == NULL) {
   	file_farhostname1 = fopen(path_farhostname1, "w+");
   	fprintf(file_farhostname1,"hostname1=NULL\n");
   	rewind(file_farhostname1);
   	}

   	char path_farhostname2[100];
   	sprintf(path_farhostname2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.2", hostname);
  	FILE *file_farhostname2;
	file_farhostname2 = fopen(path_farhostname2, "r");
   	char object_farhostname2[100];

 	if (file_farhostname2 == NULL) {
   	file_farhostname2 = fopen(path_farhostname2, "w+");
   	fprintf(file_farhostname2,"hostname2=NULL\n");
   	rewind(file_farhostname2);
   	}

   	char path_farhostname3[100];
   	sprintf(path_farhostname3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.3", hostname);
  	FILE *file_farhostname3;
	file_farhostname3 = fopen(path_farhostname3, "r");
   	char object_farhostname3[100];

 	if (file_farhostname3 == NULL) {
   	file_farhostname3 = fopen(path_farhostname3, "w+");
   	fprintf(file_farhostname3,"hostname3=NULL\n");
   	rewind(file_farhostname3);
   	}

   	char path_farhostname4[100];
   	sprintf(path_farhostname4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.4", hostname);
  	FILE *file_farhostname4;
	file_farhostname4 = fopen(path_farhostname4, "r");
   	char object_farhostname4[100];

 	if (file_farhostname4 == NULL) {
   	file_farhostname4 = fopen(path_farhostname4, "w+");
   	fprintf(file_farhostname4,"hostname4=NULL\n");
   	rewind(file_farhostname4);
   	}

   	char path_farhostname5[100];
   	sprintf(path_farhostname5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.5", hostname);
  	FILE *file_farhostname5;
	file_farhostname5 = fopen(path_farhostname5, "r");
   	char object_farhostname5[100];

 	if (file_farhostname5 == NULL) {
   	file_farhostname5 = fopen(path_farhostname5, "w+");
   	fprintf(file_farhostname5,"hostname5=NULL\n");
   	rewind(file_farhostname5);
   	}

   	char path_farhostname6[100];
   	sprintf(path_farhostname6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.6", hostname);
  	FILE *file_farhostname6;
	file_farhostname6 = fopen(path_farhostname6, "r");
   	char object_farhostname6[100];

 	if (file_farhostname6 == NULL) {
   	file_farhostname6 = fopen(path_farhostname6, "w+");
   	fprintf(file_farhostname6,"hostname6=NULL\n");
   	rewind(file_farhostname6);
   	}

   	char path_farhostname7[100];
   	sprintf(path_farhostname7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.7", hostname);
  	FILE *file_farhostname7;
	file_farhostname7 = fopen(path_farhostname7, "r");
   	char object_farhostname7[100];

 	if (file_farhostname7 == NULL) {
   	file_farhostname7 = fopen(path_farhostname7, "w+");
   	fprintf(file_farhostname7,"hostname7=NULL\n");
   	rewind(file_farhostname7);
   	}

   	char path_farhostname8[100];
   	sprintf(path_farhostname8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.8", hostname);
  	FILE *file_farhostname8;
	file_farhostname8 = fopen(path_farhostname8, "r");
   	char object_farhostname8[100];

 	if (file_farhostname8 == NULL) {
   	file_farhostname8 = fopen(path_farhostname8, "w+");
   	fprintf(file_farhostname8,"hostname8=NULL\n");
   	rewind(file_farhostname8);
   	}

  	char path_fartime0[100];
  	sprintf(path_fartime0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.0", hostname);
   	FILE *file_fartime0;
   	file_fartime0 = fopen(path_fartime0, "r");
   	char object_fartime0[100];

 	if (file_fartime0 == NULL) {
   	file_fartime0 = fopen(path_fartime0, "w+");
   	fprintf(file_fartime0,"time0=NULL\n");
   	rewind(file_fartime0);
   	}

  	char path_fartime1[100];
  	sprintf(path_fartime1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.1", hostname);
   	FILE *file_fartime1;
   	file_fartime1 = fopen(path_fartime1, "r");
   	char object_fartime1[100];

 	if (file_fartime1 == NULL) {
   	file_fartime1 = fopen(path_fartime1, "w+");
   	fprintf(file_fartime1,"time1=NULL\n");
   	rewind(file_fartime1);
   	}

  	char path_fartime2[100];
  	sprintf(path_fartime2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.2", hostname);
   	FILE *file_fartime2;
   	file_fartime2 = fopen(path_fartime2, "r");
   	char object_fartime2[100];

 	if (file_fartime2 == NULL) {
   	file_fartime2 = fopen(path_fartime2, "w+");
   	fprintf(file_fartime2,"time2=NULL\n");
   	rewind(file_fartime2);
   	}

  	char path_fartime3[100];
  	sprintf(path_fartime3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.3", hostname);
   	FILE *file_fartime3;
   	file_fartime3 = fopen(path_fartime3, "r");
   	char object_fartime3[100];

 	if (file_fartime3 == NULL) {
   	file_fartime3 = fopen(path_fartime3, "w+");
   	fprintf(file_fartime3,"time3=NULL\n");
   	rewind(file_fartime3);
   	}

  	char path_fartime4[100];
  	sprintf(path_fartime4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.4", hostname);
   	FILE *file_fartime4;
   	file_fartime4 = fopen(path_fartime4, "r");
   	char object_fartime4[100];

 	if (file_fartime4 == NULL) {
   	file_fartime4 = fopen(path_fartime4, "w+");
   	fprintf(file_fartime4,"time4=NULL\n");
   	rewind(file_fartime4);
   	}

  	char path_fartime5[100];
  	sprintf(path_fartime5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.5", hostname);
   	FILE *file_fartime5;
   	file_fartime5 = fopen(path_fartime5, "r");
   	char object_fartime5[100];

 	if (file_fartime5 == NULL) {
   	file_fartime5 = fopen(path_fartime5, "w+");
   	fprintf(file_fartime5,"time5=NULL\n");
   	rewind(file_fartime5);
   	}

  	char path_fartime6[100];
  	sprintf(path_fartime6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.6", hostname);
   	FILE *file_fartime6;
   	file_fartime6 = fopen(path_fartime6, "r");
   	char object_fartime6[100];

 	if (file_fartime6 == NULL) {
   	file_fartime6 = fopen(path_fartime6, "w+");
   	fprintf(file_fartime6,"time6=NULL\n");
   	rewind(file_fartime6);
   	}

  	char path_fartime7[100];
  	sprintf(path_fartime7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.7", hostname);
   	FILE *file_fartime7;
   	file_fartime7 = fopen(path_fartime7, "r");
   	char object_fartime7[100];

 	if (file_fartime7 == NULL) {
   	file_fartime7 = fopen(path_fartime7, "w+");
   	fprintf(file_fartime7,"time7=NULL\n");
   	rewind(file_fartime7);
   	}

  	char path_fartime8[100];
  	sprintf(path_fartime8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.8", hostname);
   	FILE *file_fartime8;
   	file_fartime8 = fopen(path_fartime8, "r");
   	char object_fartime8[100];

 	if (file_fartime8 == NULL) {
   	file_fartime8 = fopen(path_fartime8, "w+");
   	fprintf(file_fartime8,"time8=NULL\n");
   	rewind(file_fartime8);
   	}

//valores de cada objeto de ccndStatus/faceActivityRates
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE0] = strdup (fgets (object_farface0, sizeof(object_farface0), file_farface0)); fclose(file_farface0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE1] = strdup (fgets (object_farface1, sizeof(object_farface1), file_farface1)); fclose(file_farface1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE2] = strdup (fgets (object_farface2, sizeof(object_farface2), file_farface2)); fclose(file_farface2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE3] = strdup (fgets (object_farface3, sizeof(object_farface3), file_farface3)); fclose(file_farface3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE4] = strdup (fgets (object_farface4, sizeof(object_farface4), file_farface4)); fclose(file_farface4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE5] = strdup (fgets (object_farface5, sizeof(object_farface5), file_farface5)); fclose(file_farface5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE6] = strdup (fgets (object_farface6, sizeof(object_farface6), file_farface6)); fclose(file_farface6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE7] = strdup (fgets (object_farface7, sizeof(object_farface7), file_farface7)); fclose(file_farface7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE8] = strdup (fgets (object_farface8, sizeof(object_farface8), file_farface8)); fclose(file_farface8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN0] = strdup (fgets (object_farBIn0, sizeof(object_farBIn0), file_farBIn0)); fclose(file_farBIn0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN1] = strdup (fgets (object_farBIn1, sizeof(object_farBIn1), file_farBIn1)); fclose(file_farBIn1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN2] = strdup (fgets (object_farBIn2, sizeof(object_farBIn2), file_farBIn2)); fclose(file_farBIn2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN3] = strdup (fgets (object_farBIn3, sizeof(object_farBIn3), file_farBIn3)); fclose(file_farBIn3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN4] = strdup (fgets (object_farBIn4, sizeof(object_farBIn4), file_farBIn4)); fclose(file_farBIn4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN5] = strdup (fgets (object_farBIn5, sizeof(object_farBIn5), file_farBIn5)); fclose(file_farBIn5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN6] = strdup (fgets (object_farBIn6, sizeof(object_farBIn6), file_farBIn6)); fclose(file_farBIn6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN7] = strdup (fgets (object_farBIn7, sizeof(object_farBIn7), file_farBIn7)); fclose(file_farBIn7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN8] = strdup (fgets (object_farBIn8, sizeof(object_farBIn8), file_farBIn8)); fclose(file_farBIn8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT0] = strdup (fgets (object_farBOut0, sizeof(object_farBOut0), file_farBOut0)); fclose(file_farBOut0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT1] = strdup (fgets (object_farBOut1, sizeof(object_farBOut1), file_farBOut1)); fclose(file_farBOut1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT2] = strdup (fgets (object_farBOut2, sizeof(object_farBOut2), file_farBOut2)); fclose(file_farBOut2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT3] = strdup (fgets (object_farBOut3, sizeof(object_farBOut3), file_farBOut3)); fclose(file_farBOut3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT4] = strdup (fgets (object_farBOut4, sizeof(object_farBOut4), file_farBOut4)); fclose(file_farBOut4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT5] = strdup (fgets (object_farBOut5, sizeof(object_farBOut5), file_farBOut5)); fclose(file_farBOut5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT6] = strdup (fgets (object_farBOut6, sizeof(object_farBOut6), file_farBOut6)); fclose(file_farBOut6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT7] = strdup (fgets (object_farBOut7, sizeof(object_farBOut7), file_farBOut7)); fclose(file_farBOut7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT8] = strdup (fgets (object_farBOut8, sizeof(object_farBOut8), file_farBOut8)); fclose(file_farBOut8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA0] = strdup (fgets (object_farrData0, sizeof(object_farrData0), file_farrData0)); fclose(file_farrData0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA1] = strdup (fgets (object_farrData1, sizeof(object_farrData1), file_farrData1)); fclose(file_farrData1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA2] = strdup (fgets (object_farrData2, sizeof(object_farrData2), file_farrData2)); fclose(file_farrData2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA3] = strdup (fgets (object_farrData3, sizeof(object_farrData3), file_farrData3)); fclose(file_farrData3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA4] = strdup (fgets (object_farrData4, sizeof(object_farrData4), file_farrData4)); fclose(file_farrData4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA5] = strdup (fgets (object_farrData5, sizeof(object_farrData5), file_farrData5)); fclose(file_farrData5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA6] = strdup (fgets (object_farrData6, sizeof(object_farrData6), file_farrData6)); fclose(file_farrData6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA7] = strdup (fgets (object_farrData7, sizeof(object_farrData7), file_farrData7)); fclose(file_farrData7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA8] = strdup (fgets (object_farrData8, sizeof(object_farrData8), file_farrData8)); fclose(file_farrData8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA0] = strdup (fgets (object_farsData0, sizeof(object_farsData0), file_farsData0)); fclose(file_farsData0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA1] = strdup (fgets (object_farsData1, sizeof(object_farsData1), file_farsData1)); fclose(file_farsData1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA2] = strdup (fgets (object_farsData2, sizeof(object_farsData2), file_farsData2)); fclose(file_farsData2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA3] = strdup (fgets (object_farsData3, sizeof(object_farsData3), file_farsData3)); fclose(file_farsData3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA4] = strdup (fgets (object_farsData4, sizeof(object_farsData4), file_farsData4)); fclose(file_farsData4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA5] = strdup (fgets (object_farsData5, sizeof(object_farsData5), file_farsData5)); fclose(file_farsData5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA6] = strdup (fgets (object_farsData6, sizeof(object_farsData6), file_farsData6)); fclose(file_farsData6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA7] = strdup (fgets (object_farsData7, sizeof(object_farsData7), file_farsData7)); fclose(file_farsData7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA8] = strdup (fgets (object_farsData8, sizeof(object_farsData8), file_farsData8)); fclose(file_farsData8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED0] = strdup (fgets (object_farrInt0, sizeof(object_farrInt0), file_farrInt0)); fclose(file_farrInt0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED1] = strdup (fgets (object_farrInt1, sizeof(object_farrInt1), file_farrInt1)); fclose(file_farrInt1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED2] = strdup (fgets (object_farrInt2, sizeof(object_farrInt2), file_farrInt2)); fclose(file_farrInt2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED3] = strdup (fgets (object_farrInt3, sizeof(object_farrInt3), file_farrInt3)); fclose(file_farrInt3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED4] = strdup (fgets (object_farrInt4, sizeof(object_farrInt4), file_farrInt4)); fclose(file_farrInt4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED5] = strdup (fgets (object_farrInt5, sizeof(object_farrInt5), file_farrInt5)); fclose(file_farrInt5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED6] = strdup (fgets (object_farrInt6, sizeof(object_farrInt6), file_farrInt6)); fclose(file_farrInt6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED7] = strdup (fgets (object_farrInt7, sizeof(object_farrInt7), file_farrInt7)); fclose(file_farrInt7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED8] = strdup (fgets (object_farrInt8, sizeof(object_farrInt8), file_farrInt8)); fclose(file_farrInt8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT0] = strdup (fgets (object_farsInt0, sizeof(object_farsInt0), file_farsInt0)); fclose(file_farsInt0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT1] = strdup (fgets (object_farsInt1, sizeof(object_farsInt1), file_farsInt1)); fclose(file_farsInt1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT2] = strdup (fgets (object_farsInt2, sizeof(object_farsInt2), file_farsInt2)); fclose(file_farsInt2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT3] = strdup (fgets (object_farsInt3, sizeof(object_farsInt3), file_farsInt3)); fclose(file_farsInt3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT4] = strdup (fgets (object_farsInt4, sizeof(object_farsInt4), file_farsInt4)); fclose(file_farsInt4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT5] = strdup (fgets (object_farsInt5, sizeof(object_farsInt5), file_farsInt5)); fclose(file_farsInt5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT6] = strdup (fgets (object_farsInt6, sizeof(object_farsInt6), file_farsInt6)); fclose(file_farsInt6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT7] = strdup (fgets (object_farsInt7, sizeof(object_farsInt7), file_farsInt7)); fclose(file_farsInt7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT8] = strdup (fgets (object_farsInt8, sizeof(object_farsInt8), file_farsInt8)); fclose(file_farsInt8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST0] = strdup (fgets (object_farhostname0, sizeof(object_farhostname0), file_farhostname0)); fclose(file_farhostname0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST1] = strdup (fgets (object_farhostname1, sizeof(object_farhostname1), file_farhostname1)); fclose(file_farhostname1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST2] = strdup (fgets (object_farhostname2, sizeof(object_farhostname2), file_farhostname2)); fclose(file_farhostname2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST3] = strdup (fgets (object_farhostname3, sizeof(object_farhostname3), file_farhostname3)); fclose(file_farhostname3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST4] = strdup (fgets (object_farhostname4, sizeof(object_farhostname4), file_farhostname4)); fclose(file_farhostname4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST5] = strdup (fgets (object_farhostname5, sizeof(object_farhostname5), file_farhostname5)); fclose(file_farhostname5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST6] = strdup (fgets (object_farhostname6, sizeof(object_farhostname6), file_farhostname6)); fclose(file_farhostname6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST7] = strdup (fgets (object_farhostname7, sizeof(object_farhostname7), file_farhostname7)); fclose(file_farhostname7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST8] = strdup (fgets (object_farhostname8, sizeof(object_farhostname8), file_farhostname8)); fclose(file_farhostname8);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP0] = strdup (fgets (object_fartime0, sizeof(object_fartime0), file_fartime0)); fclose(file_fartime0);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP1] = strdup (fgets (object_fartime1, sizeof(object_fartime1), file_fartime1)); fclose(file_fartime1);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP2] = strdup (fgets (object_fartime2, sizeof(object_fartime2), file_fartime2)); fclose(file_fartime2);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP3] = strdup (fgets (object_fartime3, sizeof(object_fartime3), file_fartime3)); fclose(file_fartime3);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP4] = strdup (fgets (object_fartime4, sizeof(object_fartime4), file_fartime4)); fclose(file_fartime4);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP5] = strdup (fgets (object_fartime5, sizeof(object_fartime5), file_fartime5)); fclose(file_fartime5);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP6] = strdup (fgets (object_fartime6, sizeof(object_fartime6), file_fartime6)); fclose(file_fartime6);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP7] = strdup (fgets (object_fartime7, sizeof(object_fartime7), file_fartime7)); fclose(file_fartime7);
   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP8] = strdup (fgets (object_fartime8, sizeof(object_fartime8), file_fartime8)); fclose(file_fartime8);

//leitura de arquivos com conteudo de cada objeto de ccndStatus/forwarding

   	char path_fwface0[100];
   	sprintf(path_fwface0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.0", hostname);
   	FILE *file_fwface0;
   	file_fwface0 = fopen(path_fwface0, "r");
   	char object_fwface0[100];

 	if (file_fwface0 == NULL) {
   	file_fwface0 = fopen(path_fwface0, "w+");
   	fprintf(file_fwface0,"face0=NULL\n");
   	rewind(file_fwface0);
   	}

   	char path_fwface1[100];
   	sprintf(path_fwface1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.1", hostname);
   	FILE *file_fwface1;
   	file_fwface1 = fopen(path_fwface1, "r");
   	char object_fwface1[100];

 	if (file_fwface1 == NULL) {
   	file_fwface1 = fopen(path_fwface1, "w+");
   	fprintf(file_fwface1,"face1=NULL\n");
   	rewind(file_fwface1);
   	}

   	char path_fwface2[100];
   	sprintf(path_fwface2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.2", hostname);
   	FILE *file_fwface2;
   	file_fwface2 = fopen(path_fwface2, "r");
   	char object_fwface2[100];

 	if (file_fwface2== NULL) {
   	file_fwface2 = fopen(path_fwface2, "w+");
   	fprintf(file_fwface2,"face2=NULL\n");
   	rewind(file_fwface2);
   	}

   	char path_fwface3[100];
   	sprintf(path_fwface3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.3", hostname);
   	FILE *file_fwface3;
   	file_fwface3 = fopen(path_fwface3, "r");
   	char object_fwface3[100];

 	if (file_fwface3 == NULL) {
   	file_fwface3 = fopen(path_fwface3, "w+");
   	fprintf(file_fwface3,"face3=NULL\n");
   	rewind(file_fwface3);
   	}

   	char path_fwface4[100];
   	sprintf(path_fwface4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.4", hostname);
   	FILE *file_fwface4;
   	file_fwface4 = fopen(path_fwface4, "r");
   	char object_fwface4[100];

 	if (file_fwface4 == NULL) {
   	file_fwface4 = fopen(path_fwface4, "w+");
   	fprintf(file_fwface4,"face4=NULL\n");
   	rewind(file_fwface4);
   	}

   	char path_fwface5[100];
   	sprintf(path_fwface5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.5", hostname);
   	FILE *file_fwface5;
   	file_fwface5 = fopen(path_fwface5, "r");
   	char object_fwface5[100];

 	if (file_fwface5 == NULL) {
   	file_fwface5 = fopen(path_fwface5, "w+");
   	fprintf(file_fwface5,"face5=NULL\n");
   	rewind(file_fwface5);
   	}

   	char path_fwface6[100];
   	sprintf(path_fwface6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.6", hostname);
   	FILE *file_fwface6;
   	file_fwface6 = fopen(path_fwface6, "r");
   	char object_fwface6[100];

 	if (file_fwface6 == NULL) {
   	file_fwface6 = fopen(path_fwface6, "w+");
   	fprintf(file_fwface6,"face6=NULL\n");
   	rewind(file_fwface6);
   	}

   	char path_fwface7[100];
   	sprintf(path_fwface7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.7", hostname);
   	FILE *file_fwface7;
   	file_fwface7 = fopen(path_fwface7, "r");
   	char object_fwface7[100];

 	if (file_fwface7 == NULL) {
   	file_fwface7 = fopen(path_fwface7, "w+");
   	fprintf(file_fwface7,"face7=NULL\n");
   	rewind(file_fwface7);
   	}

   	char path_fwface8[100];
   	sprintf(path_fwface8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.8", hostname);
   	FILE *file_fwface8;
   	file_fwface8 = fopen(path_fwface8, "r");
   	char object_fwface8[100];

 	if (file_fwface8 == NULL) {
   	file_fwface8 = fopen(path_fwface8, "w+");
   	fprintf(file_fwface8,"face8=NULL\n");
   	rewind(file_fwface8);
   	}

   	char path_fwface9[100];
   	sprintf(path_fwface9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.9", hostname);
   	FILE *file_fwface9;
   	file_fwface9 = fopen(path_fwface9, "r");
   	char object_fwface9[100];

 	if (file_fwface9 == NULL) {
   	file_fwface9 = fopen(path_fwface9, "w+");
   	fprintf(file_fwface9,"face9=NULL\n");
   	rewind(file_fwface9);
   	}

   	char path_fwface10[100];
   	sprintf(path_fwface10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.10", hostname);
   	FILE *file_fwface10;
   	file_fwface10 = fopen(path_fwface10, "r");
   	char object_fwface10[100];

 	if (file_fwface10 == NULL) {
   	file_fwface10 = fopen(path_fwface10, "w+");
   	fprintf(file_fwface10,"face10=NULL\n");
   	rewind(file_fwface10);
   	}

   	char path_fwflags0[100];
   	sprintf(path_fwflags0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.0", hostname);
   	FILE *file_fwflags0;
   	file_fwflags0 = fopen(path_fwflags0, "r");
   	char object_fwflags0[100];

 	if (file_fwflags0 == NULL) {
   	file_fwflags0 = fopen(path_fwflags0, "w+");
   	fprintf(file_fwflags0,"flags0=NULL\n");
   	rewind(file_fwflags0);
   	}

   	char path_fwflags1[100];
   	sprintf(path_fwflags1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.1", hostname);
   	FILE *file_fwflags1;
   	file_fwflags1 = fopen(path_fwflags1, "r");
   	char object_fwflags1[100];

 	if (file_fwflags1 == NULL) {
   	file_fwflags1 = fopen(path_fwflags1, "w+");
   	fprintf(file_fwflags1,"flags1=NULL\n");
   	rewind(file_fwflags1);
   	}

   	char path_fwflags2[100];
   	sprintf(path_fwflags2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.2", hostname);
   	FILE *file_fwflags2;
   	file_fwflags2 = fopen(path_fwflags2, "r");
   	char object_fwflags2[100];

 	if (file_fwflags2 == NULL) {
   	file_fwflags2 = fopen(path_fwflags2, "w+");
   	fprintf(file_fwflags2,"flags2=NULL\n");
   	rewind(file_fwflags2);
   	}

   	char path_fwflags3[100];
   	sprintf(path_fwflags3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.3", hostname);
   	FILE *file_fwflags3;
   	file_fwflags3 = fopen(path_fwflags3, "r");
   	char object_fwflags3[100];

 	if (file_fwflags3 == NULL) {
   	file_fwflags3 = fopen(path_fwflags3, "w+");
   	fprintf(file_fwflags3,"flags3=NULL\n");
   	rewind(file_fwflags3);
   	}

   	char path_fwflags4[100];
   	sprintf(path_fwflags4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.4", hostname);
   	FILE *file_fwflags4;
   	file_fwflags4 = fopen(path_fwflags4, "r");
   	char object_fwflags4[100];

 	if (file_fwflags4 == NULL) {
   	file_fwflags4 = fopen(path_fwflags4, "w+");
   	fprintf(file_fwflags4,"flags4=NULL\n");
   	rewind(file_fwflags4);
   	}

   	char path_fwflags5[100];
   	sprintf(path_fwflags5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.5", hostname);
   	FILE *file_fwflags5;
   	file_fwflags5 = fopen(path_fwflags5, "r");
   	char object_fwflags5[100];

 	if (file_fwflags5 == NULL) {
   	file_fwflags5 = fopen(path_fwflags5, "w+");
   	fprintf(file_fwflags5,"flags5=NULL\n");
   	rewind(file_fwflags5);
   	}

   	char path_fwflags6[100];
   	sprintf(path_fwflags6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.6", hostname);
   	FILE *file_fwflags6;
   	file_fwflags6 = fopen(path_fwflags6, "r");
   	char object_fwflags6[100];

 	if (file_fwflags6== NULL) {
   	file_fwflags6 = fopen(path_fwflags6, "w+");
   	fprintf(file_fwflags6,"flags6=NULL\n");
   	rewind(file_fwflags6);
   	}

   	char path_fwflags7[100];
   	sprintf(path_fwflags7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.7", hostname);
   	FILE *file_fwflags7;
   	file_fwflags7 = fopen(path_fwflags7, "r");
   	char object_fwflags7[100];

 	if (file_fwflags7 == NULL) {
   	file_fwflags7 = fopen(path_fwflags7, "w+");
   	fprintf(file_fwflags7,"flags7=NULL\n");
   	rewind(file_fwflags7);
   	}

   	char path_fwflags8[100];
   	sprintf(path_fwflags8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.8", hostname);
   	FILE *file_fwflags8;
   	file_fwflags8 = fopen(path_fwflags8, "r");
   	char object_fwflags8[100];

 	if (file_fwflags8 == NULL) {
   	file_fwflags8 = fopen(path_fwflags8, "w+");
   	fprintf(file_fwflags8,"flags8=NULL\n");
   	rewind(file_fwflags8);
   	}

   	char path_fwflags9[100];
   	sprintf(path_fwflags9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.9", hostname);
   	FILE *file_fwflags9;
   	file_fwflags9 = fopen(path_fwflags9, "r");
   	char object_fwflags9[100];

 	if (file_fwflags9 == NULL) {
   	file_fwflags9 = fopen(path_fwflags9, "w+");
   	fprintf(file_fwflags9,"flags9=NULL\n");
   	rewind(file_fwflags9);
   	}

   	char path_fwflags10[100];
   	sprintf(path_fwflags10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.10", hostname);
   	FILE *file_fwflags10;
   	file_fwflags10 = fopen(path_fwflags10, "r");
   	char object_fwflags10[100];

 	if (file_fwflags10 == NULL) {
   	file_fwflags10 = fopen(path_fwflags10, "w+");
   	fprintf(file_fwflags10,"flags10=NULL\n");
   	rewind(file_fwflags10);
   	}

   	char path_fwpath0[100];
   	sprintf(path_fwpath0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.0", hostname);
   	FILE *file_fwpath0;
   	file_fwpath0 = fopen(path_fwpath0, "r");
	char object_fwpath0[100];

 	if (file_fwpath0 == NULL) {
   	file_fwpath0 = fopen(path_fwpath0, "w+");
   	fprintf(file_fwpath0,"path0=NULL\n");
   	rewind(file_fwpath0);
   	}

   	char path_fwpath1[100];
   	sprintf(path_fwpath1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.1", hostname);
   	FILE *file_fwpath1;
   	file_fwpath1 = fopen(path_fwpath1, "r");
	char object_fwpath1[100];

 	if (file_fwpath1 == NULL) {
   	file_fwpath1 = fopen(path_fwpath1, "w+");
   	fprintf(file_fwpath1,"path1=NULL\n");
   	rewind(file_fwpath1);
   	}

   	char path_fwpath2[100];
   	sprintf(path_fwpath2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.2", hostname);
   	FILE *file_fwpath2;
   	file_fwpath2 = fopen(path_fwpath2, "r");
	char object_fwpath2[100];

 	if (file_fwpath2 == NULL) {
   	file_fwpath2 = fopen(path_fwpath2, "w+");
   	fprintf(file_fwpath2,"path2=NULL\n");
   	rewind(file_fwpath2);
   	}

   	char path_fwpath3[100];
   	sprintf(path_fwpath3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.3", hostname);
   	FILE *file_fwpath3;
   	file_fwpath3 = fopen(path_fwpath3, "r");
	char object_fwpath3[100];

 	if (file_fwpath3 == NULL) {
   	file_fwpath3 = fopen(path_fwpath3, "w+");
   	fprintf(file_fwpath3,"path3=NULL\n");
   	rewind(file_fwpath3);
   	}

   	char path_fwpath4[100];
   	sprintf(path_fwpath4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.4", hostname);
   	FILE *file_fwpath4;
   	file_fwpath4 = fopen(path_fwpath4, "r");
	char object_fwpath4[100];

 	if (file_fwpath4 == NULL) {
   	file_fwpath4 = fopen(path_fwpath0, "w+");
   	fprintf(file_fwpath4,"path4=NULL\n");
   	rewind(file_fwpath4);
   	}

   	char path_fwpath5[100];
   	sprintf(path_fwpath5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.5", hostname);
   	FILE *file_fwpath5;
   	file_fwpath5 = fopen(path_fwpath5, "r");
	char object_fwpath5[100];

 	if (file_fwpath5== NULL) {
   	file_fwpath5 = fopen(path_fwpath5, "w+");
   	fprintf(file_fwpath5,"path5=NULL\n");
   	rewind(file_fwpath5);
   	}

   	char path_fwpath6[100];
   	sprintf(path_fwpath6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.6", hostname);
   	FILE *file_fwpath6;
   	file_fwpath6 = fopen(path_fwpath6, "r");
	char object_fwpath6[100];

 	if (file_fwpath6 == NULL) {
   	file_fwpath6 = fopen(path_fwpath6, "w+");
   	fprintf(file_fwpath6,"path6=NULL\n");
   	rewind(file_fwpath6);
   	}

   	char path_fwpath7[100];
   	sprintf(path_fwpath7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.7", hostname);
   	FILE *file_fwpath7;
   	file_fwpath7 = fopen(path_fwpath7, "r");
	char object_fwpath7[100];

 	if (file_fwpath7 == NULL) {
   	file_fwpath7 = fopen(path_fwpath7, "w+");
   	fprintf(file_fwpath7,"path7=NULL\n");
   	rewind(file_fwpath7);
   	}

   	char path_fwpath8[100];
   	sprintf(path_fwpath8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.8", hostname);
   	FILE *file_fwpath8;
   	file_fwpath8 = fopen(path_fwpath8, "r");
	char object_fwpath8[100];

 	if (file_fwpath8 == NULL) {
   	file_fwpath8 = fopen(path_fwpath8, "w+");
   	fprintf(file_fwpath8,"path8=NULL\n");
   	rewind(file_fwpath8);
   	}

   	char path_fwpath9[100];
   	sprintf(path_fwpath9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.9", hostname);
   	FILE *file_fwpath9;
   	file_fwpath9 = fopen(path_fwpath9, "r");
	char object_fwpath9[100];

 	if (file_fwpath9 == NULL) {
   	file_fwpath9 = fopen(path_fwpath9, "w+");
   	fprintf(file_fwpath9,"fwpath9=NULL\n");
   	rewind(file_fwpath9);
   	}

   	char path_fwpath10[100];
   	sprintf(path_fwpath10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.10", hostname);
   	FILE *file_fwpath10;
   	file_fwpath10 = fopen(path_fwpath10, "r");
	char object_fwpath10[100];

 	if (file_fwpath10 == NULL) {
   	file_fwpath10 = fopen(path_fwpath10, "w+");
   	fprintf(file_fwpath10,"path10=NULL\n");
   	rewind(file_fwpath10);
   	}

  	char path_fwexpires0[100];
  	sprintf(path_fwexpires0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.0", hostname);
   	FILE *file_fwexpires0;
   	file_fwexpires0 = fopen(path_fwexpires0, "r");
   	char object_fwexpires0[100];

 	if (file_fwexpires0 == NULL) {
   	file_fwexpires0 = fopen(path_fwexpires0, "w+");
   	fprintf(file_fwexpires0,"expires0=NULL\n");
   	rewind(file_fwexpires0);
   	}

  	char path_fwexpires1[100];
  	sprintf(path_fwexpires1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.1", hostname);
   	FILE *file_fwexpires1;
   	file_fwexpires1 = fopen(path_fwexpires1, "r");
   	char object_fwexpires1[100];

 	if (file_fwexpires1 == NULL) {
   	file_fwexpires1 = fopen(path_fwexpires1, "w+");
   	fprintf(file_fwexpires1,"expires1=NULL\n");
   	rewind(file_fwexpires1);
   	}

  	char path_fwexpires2[100];
  	sprintf(path_fwexpires2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.2", hostname);
   	FILE *file_fwexpires2;
   	file_fwexpires2 = fopen(path_fwexpires2, "r");
   	char object_fwexpires2[100];

 	if (file_fwexpires2 == NULL) {
   	file_fwexpires2 = fopen(path_fwexpires2, "w+");
   	fprintf(file_fwexpires2,"expires2=NULL\n");
   	rewind(file_fwexpires2);
   	}

  	char path_fwexpires3[100];
  	sprintf(path_fwexpires3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.3", hostname);
   	FILE *file_fwexpires3;
   	file_fwexpires3 = fopen(path_fwexpires3, "r");
   	char object_fwexpires3[100];

 	if (file_fwexpires3 == NULL) {
   	file_fwexpires3 = fopen(path_fwexpires3, "w+");
   	fprintf(file_fwexpires3,"expires3=NULL\n");
   	rewind(file_fwexpires3);
   	}

  	char path_fwexpires4[100];
  	sprintf(path_fwexpires4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.4", hostname);
   	FILE *file_fwexpires4;
   	file_fwexpires4 = fopen(path_fwexpires4, "r");
   	char object_fwexpires4[100];

 	if (file_fwexpires4 == NULL) {
   	file_fwexpires4 = fopen(path_fwexpires4, "w+");
   	fprintf(file_fwexpires4,"expires4=NULL\n");
   	rewind(file_fwexpires4);
   	}

  	char path_fwexpires5[100];
  	sprintf(path_fwexpires5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.5", hostname);
   	FILE *file_fwexpires5;
   	file_fwexpires5 = fopen(path_fwexpires5, "r");
   	char object_fwexpires5[100];

 	if (file_fwexpires5 == NULL) {
   	file_fwexpires5 = fopen(path_fwexpires5, "w+");
   	fprintf(file_fwexpires5,"expires5=NULL\n");
   	rewind(file_fwexpires5);
   	}

  	char path_fwexpires6[100];
  	sprintf(path_fwexpires6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.6", hostname);
   	FILE *file_fwexpires6;
   	file_fwexpires6 = fopen(path_fwexpires6, "r");
   	char object_fwexpires6[100];

 	if (file_fwexpires6 == NULL) {
   	file_fwexpires6 = fopen(path_fwexpires6, "w+");
   	fprintf(file_fwexpires6,"expires6=NULL\n");
   	rewind(file_fwexpires6);
   	}

  	char path_fwexpires7[100];
  	sprintf(path_fwexpires7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.7", hostname);
   	FILE *file_fwexpires7;
   	file_fwexpires7 = fopen(path_fwexpires7, "r");
   	char object_fwexpires7[100];

 	if (file_fwexpires7 == NULL) {
   	file_fwexpires7 = fopen(path_fwexpires7, "w+");
   	fprintf(file_fwexpires7,"expires7=NULL\n");
   	rewind(file_fwexpires7);
   	}

  	char path_fwexpires8[100];
  	sprintf(path_fwexpires8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.8", hostname);
   	FILE *file_fwexpires8;
   	file_fwexpires8 = fopen(path_fwexpires8, "r");
   	char object_fwexpires8[100];

 	if (file_fwexpires8 == NULL) {
   	file_fwexpires8 = fopen(path_fwexpires8, "w+");
   	fprintf(file_fwexpires8,"expires8=NULL\n");
   	rewind(file_fwexpires8);
   	}

  	char path_fwexpires9[100];
  	sprintf(path_fwexpires9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.9", hostname);
   	FILE *file_fwexpires9;
   	file_fwexpires9 = fopen(path_fwexpires9, "r");
   	char object_fwexpires9[100];

 	if (file_fwexpires9 == NULL) {
   	file_fwexpires9 = fopen(path_fwexpires9, "w+");
   	fprintf(file_fwexpires9,"expires9=NULL\n");
   	rewind(file_fwexpires9);
   	}

  	char path_fwexpires10[100];
  	sprintf(path_fwexpires10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.10", hostname);
   	FILE *file_fwexpires10;
   	file_fwexpires10 = fopen(path_fwexpires10, "r");
   	char object_fwexpires10[100];

 	if (file_fwexpires10 == NULL) {
   	file_fwexpires10 = fopen(path_fwexpires10, "w+");
   	fprintf(file_fwexpires10,"expires10=NULL\n");
   	rewind(file_fwexpires10);
   	}

   	char path_fwhostname0[100];
   	sprintf(path_fwhostname0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.0", hostname);
  	FILE *file_fwhostname0;
	file_fwhostname0 = fopen(path_fwhostname0, "r");
   	char object_fwhostname0[100];

 	if (file_fwhostname0 == NULL) {
   	file_fwhostname0 = fopen(path_fwhostname0, "w+");
   	fprintf(file_fwhostname0,"hostname0=NULL\n");
   	rewind(file_fwhostname0);
   	}

   	char path_fwhostname1[100];
   	sprintf(path_fwhostname1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.1", hostname);
  	FILE *file_fwhostname1;
	file_fwhostname1 = fopen(path_fwhostname1, "r");
   	char object_fwhostname1[100];

 	if (file_fwhostname1 == NULL) {
   	file_fwhostname1 = fopen(path_fwhostname1, "w+");
   	fprintf(file_fwhostname1,"hostname1=NULL\n");
   	rewind(file_fwhostname1);
   	}

   	char path_fwhostname2[100];
   	sprintf(path_fwhostname2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.2", hostname);
  	FILE *file_fwhostname2;
	file_fwhostname2 = fopen(path_fwhostname2, "r");
   	char object_fwhostname2[100];

 	if (file_fwhostname2 == NULL) {
   	file_fwhostname2 = fopen(path_fwhostname0, "w+");
   	fprintf(file_fwhostname2,"hostname2=NULL\n");
   	rewind(file_fwhostname2);
   	}

   	char path_fwhostname3[100];
   	sprintf(path_fwhostname3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.3", hostname);
  	FILE *file_fwhostname3;
	file_fwhostname3 = fopen(path_fwhostname3, "r");
   	char object_fwhostname3[100];

 	if (file_fwhostname3 == NULL) {
   	file_fwhostname3 = fopen(path_fwhostname3, "w+");
   	fprintf(file_fwhostname3,"hostname3=NULL\n");
   	rewind(file_fwhostname3);
   	}

   	char path_fwhostname4[100];
   	sprintf(path_fwhostname4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.4", hostname);
  	FILE *file_fwhostname4;
	file_fwhostname4 = fopen(path_fwhostname4, "r");
   	char object_fwhostname4[100];

 	if (file_fwhostname4 == NULL) {
   	file_fwhostname4 = fopen(path_fwhostname4, "w+");
   	fprintf(file_fwhostname4,"hostname4=NULL\n");
   	rewind(file_fwhostname4);
   	}

   	char path_fwhostname5[100];
   	sprintf(path_fwhostname5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.5", hostname);
  	FILE *file_fwhostname5;
	file_fwhostname5 = fopen(path_fwhostname5, "r");
   	char object_fwhostname5[100];

 	if (file_fwhostname5 == NULL) {
   	file_fwhostname5 = fopen(path_fwhostname5, "w+");
   	fprintf(file_fwhostname5,"hostname5=NULL\n");
   	rewind(file_fwhostname5);
   	}

   	char path_fwhostname6[100];
   	sprintf(path_fwhostname6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.6", hostname);
  	FILE *file_fwhostname6;
	file_fwhostname6 = fopen(path_fwhostname6, "r");
   	char object_fwhostname6[100];

 	if (file_fwhostname6 == NULL) {
   	file_fwhostname6 = fopen(path_fwhostname6, "w+");
   	fprintf(file_fwhostname6,"hostname6=NULL\n");
   	rewind(file_fwhostname6);
   	}

   	char path_fwhostname7[100];
   	sprintf(path_fwhostname7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.7", hostname);
  	FILE *file_fwhostname7;
	file_fwhostname7 = fopen(path_fwhostname7, "r");
   	char object_fwhostname7[100];

 	if (file_fwhostname7 == NULL) {
   	file_fwhostname7 = fopen(path_fwhostname7, "w+");
   	fprintf(file_fwhostname7,"hostname7=NULL\n");
   	rewind(file_fwhostname7);
   	}

   	char path_fwhostname8[100];
   	sprintf(path_fwhostname8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.8", hostname);
  	FILE *file_fwhostname8;
	file_fwhostname8 = fopen(path_fwhostname8, "r");
   	char object_fwhostname8[100];

 	if (file_fwhostname8 == NULL) {
   	file_fwhostname8 = fopen(path_fwhostname8, "w+");
   	fprintf(file_fwhostname8,"hostname8=NULL\n");
   	rewind(file_fwhostname8);
   	}

   	char path_fwhostname9[100];
   	sprintf(path_fwhostname9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.9", hostname);
  	FILE *file_fwhostname9;
	file_fwhostname9 = fopen(path_fwhostname9, "r");
   	char object_fwhostname9[100];

 	if (file_fwhostname9 == NULL) {
   	file_fwhostname9 = fopen(path_fwhostname9, "w+");
   	fprintf(file_fwhostname9,"hostname9=NULL\n");
   	rewind(file_fwhostname9);
   	}

   	char path_fwhostname10[100];
   	sprintf(path_fwhostname10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.10", hostname);
  	FILE *file_fwhostname10;
	file_fwhostname10 = fopen(path_fwhostname10, "r");
   	char object_fwhostname10[100];

 	if (file_fwhostname10 == NULL) {
   	file_fwhostname10 = fopen(path_fwhostname10, "w+");
   	fprintf(file_fwhostname10,"hostname10=NULL\n");
   	rewind(file_fwhostname10);
   	}

  	char path_fwtime0[100];
  	sprintf(path_fwtime0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.0", hostname);
   	FILE *file_fwtime0;
   	file_fwtime0 = fopen(path_fwtime0, "r");
   	char object_fwtime0[100];

 	if (file_fwtime0 == NULL) {
   	file_fwtime0 = fopen(path_fwtime0, "w+");
   	fprintf(file_fwtime0,"time0=NULL\n");
   	rewind(file_fwtime0);
   	}

  	char path_fwtime1[100];
  	sprintf(path_fwtime1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.1", hostname);
   	FILE *file_fwtime1;
   	file_fwtime1 = fopen(path_fwtime1, "r");
   	char object_fwtime1[100];

 	if (file_fwtime1 == NULL) {
   	file_fwtime1 = fopen(path_fwtime1, "w+");
   	fprintf(file_fwtime1,"time1=NULL\n");
   	rewind(file_fwtime0);
   	}

  	char path_fwtime2[100];
  	sprintf(path_fwtime2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.2", hostname);
   	FILE *file_fwtime2;
   	file_fwtime2 = fopen(path_fwtime2, "r");
   	char object_fwtime2[100];

 	if (file_fwtime2 == NULL) {
   	file_fwtime2 = fopen(path_fwtime2, "w+");
   	fprintf(file_fwtime2,"time2=NULL\n");
   	rewind(file_fwtime2);
   	}

  	char path_fwtime3[100];
  	sprintf(path_fwtime3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.3", hostname);
   	FILE *file_fwtime3;
   	file_fwtime3 = fopen(path_fwtime3, "r");
   	char object_fwtime3[100];

 	if (file_fwtime3 == NULL) {
   	file_fwtime3 = fopen(path_fwtime3, "w+");
   	fprintf(file_fwtime3,"time3=NULL\n");
   	rewind(file_fwtime3);
   	}

  	char path_fwtime4[100];
  	sprintf(path_fwtime4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.4", hostname);
   	FILE *file_fwtime4;
   	file_fwtime4 = fopen(path_fwtime4, "r");
   	char object_fwtime4[100];

 	if (file_fwtime4 == NULL) {
   	file_fwtime4 = fopen(path_fwtime4, "w+");
   	fprintf(file_fwtime4,"time4=NULL\n");
   	rewind(file_fwtime4);
   	}

  	char path_fwtime5[100];
  	sprintf(path_fwtime5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.5", hostname);
   	FILE *file_fwtime5;
   	file_fwtime5 = fopen(path_fwtime5, "r");
   	char object_fwtime5[100];

 	if (file_fwtime5 == NULL) {
   	file_fwtime5 = fopen(path_fwtime5, "w+");
   	fprintf(file_fwtime5,"time5=NULL\n");
   	rewind(file_fwtime5);
   	}

  	char path_fwtime6[100];
  	sprintf(path_fwtime6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.6", hostname);
   	FILE *file_fwtime6;
   	file_fwtime6 = fopen(path_fwtime6, "r");
   	char object_fwtime6[100];

 	if (file_fwtime6 == NULL) {
   	file_fwtime6 = fopen(path_fwtime6, "w+");
   	fprintf(file_fwtime6,"time6=NULL\n");
   	rewind(file_fwtime6);
   	}

  	char path_fwtime7[100];
  	sprintf(path_fwtime7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.7", hostname);
   	FILE *file_fwtime7;
   	file_fwtime7 = fopen(path_fwtime7, "r");
   	char object_fwtime7[100];

 	if (file_fwtime7 == NULL) {
   	file_fwtime7 = fopen(path_fwtime7, "w+");
   	fprintf(file_fwtime7,"time7=NULL\n");
   	rewind(file_fwtime7);
   	}

  	char path_fwtime8[100];
  	sprintf(path_fwtime8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.8", hostname);
   	FILE *file_fwtime8;
   	file_fwtime8 = fopen(path_fwtime8, "r");
   	char object_fwtime8[100];

 	if (file_fwtime8 == NULL) {
   	file_fwtime8 = fopen(path_fwtime8, "w+");
   	fprintf(file_fwtime8,"time8=NULL\n");
   	rewind(file_fwtime8);
   	}

  	char path_fwtime9[100];
  	sprintf(path_fwtime9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.9", hostname);
   	FILE *file_fwtime9;
   	file_fwtime9 = fopen(path_fwtime9, "r");
   	char object_fwtime9[100];

 	if (file_fwtime9 == NULL) {
   	file_fwtime9 = fopen(path_fwtime9, "w+");
   	fprintf(file_fwtime9,"time9=NULL\n");
   	rewind(file_fwtime9);
   	}

  	char path_fwtime10[100];
  	sprintf(path_fwtime1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.10", hostname);
   	FILE *file_fwtime10;
   	file_fwtime10 = fopen(path_fwtime10, "r");
   	char object_fwtime10[100];

 	if (file_fwtime10 == NULL) {
   	file_fwtime10 = fopen(path_fwtime10, "w+");
   	fprintf(file_fwtime10,"time10=NULL\n");
   	rewind(file_fwtime10);
   	}

////valores de cada objeto de ccndStatus/forwarding
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE0] = strdup (fgets (object_fwface0, sizeof(object_fwface0), file_fwface0)); fclose(file_fwface0);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE1] = strdup (fgets (object_fwface1, sizeof(object_fwface1), file_fwface1)); fclose(file_fwface1);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE2] = strdup (fgets (object_fwface2, sizeof(object_fwface2), file_fwface2)); fclose(file_fwface2);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE3] = strdup (fgets (object_fwface3, sizeof(object_fwface3), file_fwface3)); fclose(file_fwface3);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE4] = strdup (fgets (object_fwface4, sizeof(object_fwface4), file_fwface4)); fclose(file_fwface4);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE5] = strdup (fgets (object_fwface5, sizeof(object_fwface5), file_fwface5)); fclose(file_fwface5);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE6] = strdup (fgets (object_fwface6, sizeof(object_fwface6), file_fwface6)); fclose(file_fwface6);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE7] = strdup (fgets (object_fwface7, sizeof(object_fwface7), file_fwface7)); fclose(file_fwface7);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE8] = strdup (fgets (object_fwface8, sizeof(object_fwface8), file_fwface8)); fclose(file_fwface8);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE9] = strdup (fgets (object_fwface9, sizeof(object_fwface9), file_fwface9)); fclose(file_fwface9);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE10] = strdup (fgets (object_fwface10, sizeof(object_fwface10), file_fwface10)); fclose(file_fwface10);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS0] = strdup (fgets (object_fwflags0, sizeof(object_fwflags0), file_fwflags0)); fclose(file_fwflags0);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS1] = strdup (fgets (object_fwflags1, sizeof(object_fwflags1), file_fwflags1)); fclose(file_fwflags1);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS2] = strdup (fgets (object_fwflags2, sizeof(object_fwflags2), file_fwflags2)); fclose(file_fwflags2);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS3] = strdup (fgets (object_fwflags3, sizeof(object_fwflags3), file_fwflags3)); fclose(file_fwflags3);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS4] = strdup (fgets (object_fwflags4, sizeof(object_fwflags4), file_fwflags4)); fclose(file_fwflags4);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS5] = strdup (fgets (object_fwflags5, sizeof(object_fwflags5), file_fwflags5)); fclose(file_fwflags5);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS6] = strdup (fgets (object_fwflags6, sizeof(object_fwflags6), file_fwflags6)); fclose(file_fwflags6);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS7] = strdup (fgets (object_fwflags7, sizeof(object_fwflags7), file_fwflags7)); fclose(file_fwflags7);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS8] = strdup (fgets (object_fwflags8, sizeof(object_fwflags8), file_fwflags8)); fclose(file_fwflags8);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS9] = strdup (fgets (object_fwflags9, sizeof(object_fwflags9), file_fwflags9)); fclose(file_fwflags9);
	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS10] = strdup (fgets (object_fwflags10, sizeof(object_fwflags10), file_fwflags10)); fclose(file_fwflags10);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH0] = strdup (fgets (object_fwpath0, sizeof(object_fwpath0), file_fwpath0)); fclose(file_fwpath0);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH1] = strdup (fgets (object_fwpath1, sizeof(object_fwpath1), file_fwpath1)); fclose(file_fwpath1);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH2] = strdup (fgets (object_fwpath2, sizeof(object_fwpath2), file_fwpath2)); fclose(file_fwpath2);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH3] = strdup (fgets (object_fwpath3, sizeof(object_fwpath3), file_fwpath3)); fclose(file_fwpath3);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH4] = strdup (fgets (object_fwpath4, sizeof(object_fwpath4), file_fwpath4)); fclose(file_fwpath4);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH5] = strdup (fgets (object_fwpath5, sizeof(object_fwpath5), file_fwpath5)); fclose(file_fwpath5);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH6] = strdup (fgets (object_fwpath6, sizeof(object_fwpath6), file_fwpath6)); fclose(file_fwpath6);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH7] = strdup (fgets (object_fwpath7, sizeof(object_fwpath7), file_fwpath7)); fclose(file_fwpath7);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH8] = strdup (fgets (object_fwpath8, sizeof(object_fwpath8), file_fwpath8)); fclose(file_fwpath8);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH9] = strdup (fgets (object_fwpath9, sizeof(object_fwpath9), file_fwpath9)); fclose(file_fwpath9);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH10] = strdup (fgets (object_fwpath10, sizeof(object_fwpath10), file_fwpath10)); fclose(file_fwpath10);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES0] = strdup (fgets (object_fwexpires0, sizeof(object_fwexpires0), file_fwexpires0)); fclose(file_fwexpires0);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES1] = strdup (fgets (object_fwexpires1, sizeof(object_fwexpires1), file_fwexpires1)); fclose(file_fwexpires1);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES2] = strdup (fgets (object_fwexpires2, sizeof(object_fwexpires2), file_fwexpires2)); fclose(file_fwexpires2);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES3] = strdup (fgets (object_fwexpires3, sizeof(object_fwexpires3), file_fwexpires3)); fclose(file_fwexpires3);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES4] = strdup (fgets (object_fwexpires4, sizeof(object_fwexpires4), file_fwexpires4)); fclose(file_fwexpires4);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES5] = strdup (fgets (object_fwexpires5, sizeof(object_fwexpires5), file_fwexpires5)); fclose(file_fwexpires5);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES6] = strdup (fgets (object_fwexpires6, sizeof(object_fwexpires6), file_fwexpires6)); fclose(file_fwexpires6);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES7] = strdup (fgets (object_fwexpires7, sizeof(object_fwexpires7), file_fwexpires7)); fclose(file_fwexpires7);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES8] = strdup (fgets (object_fwexpires8, sizeof(object_fwexpires8), file_fwexpires8)); fclose(file_fwexpires8);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES9] = strdup (fgets (object_fwexpires9, sizeof(object_fwexpires9), file_fwexpires9)); fclose(file_fwexpires9);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES10] = strdup (fgets (object_fwexpires10, sizeof(object_fwexpires10), file_fwexpires10)); fclose(file_fwexpires10);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST0] = strdup (fgets (object_fwhostname0, sizeof(object_fwhostname0), file_fwhostname0)); fclose(file_fwhostname0);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST1] = strdup (fgets (object_fwhostname1, sizeof(object_fwhostname1), file_fwhostname1)); fclose(file_fwhostname1);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST2] = strdup (fgets (object_fwhostname2, sizeof(object_fwhostname2), file_fwhostname2)); fclose(file_fwhostname2);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST3] = strdup (fgets (object_fwhostname3, sizeof(object_fwhostname3), file_fwhostname3)); fclose(file_fwhostname3);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST4] = strdup (fgets (object_fwhostname4, sizeof(object_fwhostname4), file_fwhostname4)); fclose(file_fwhostname4);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST5] = strdup (fgets (object_fwhostname5, sizeof(object_fwhostname5), file_fwhostname5)); fclose(file_fwhostname5);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST6] = strdup (fgets (object_fwhostname6, sizeof(object_fwhostname6), file_fwhostname6)); fclose(file_fwhostname6);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST7] = strdup (fgets (object_fwhostname7, sizeof(object_fwhostname7), file_fwhostname7)); fclose(file_fwhostname7);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST8] = strdup (fgets (object_fwhostname8, sizeof(object_fwhostname8), file_fwhostname8)); fclose(file_fwhostname8);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST9] = strdup (fgets (object_fwhostname9, sizeof(object_fwhostname9), file_fwhostname9)); fclose(file_fwhostname9);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST10] = strdup (fgets (object_fwhostname10, sizeof(object_fwhostname10), file_fwhostname10)); fclose(file_fwhostname10);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP0] = strdup (fgets (object_fwtime0, sizeof(object_fwtime0), file_fwtime0)); fclose(file_fwtime0);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP1] = strdup (fgets (object_fwtime1, sizeof(object_fwtime1), file_fwtime1)); fclose(file_fwtime1);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP2] = strdup (fgets (object_fwtime2, sizeof(object_fwtime2), file_fwtime2)); fclose(file_fwtime2);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP3] = strdup (fgets (object_fwtime3, sizeof(object_fwtime3), file_fwtime3)); fclose(file_fwtime3);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP4] = strdup (fgets (object_fwtime4, sizeof(object_fwtime4), file_fwtime4)); fclose(file_fwtime4);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP5] = strdup (fgets (object_fwtime5, sizeof(object_fwtime5), file_fwtime5)); fclose(file_fwtime5);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP6] = strdup (fgets (object_fwtime6, sizeof(object_fwtime6), file_fwtime6)); fclose(file_fwtime6);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP7] = strdup (fgets (object_fwtime7, sizeof(object_fwtime7), file_fwtime7)); fclose(file_fwtime7);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP8] = strdup (fgets (object_fwtime8, sizeof(object_fwtime8), file_fwtime8)); fclose(file_fwtime8);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP9] = strdup (fgets (object_fwtime9, sizeof(object_fwtime9), file_fwtime9)); fclose(file_fwtime9);
   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP10] = strdup (fgets (object_fwtime10, sizeof(object_fwtime10), file_fwtime10)); fclose(file_fwtime10);
}

//Funcao para atualizar os valores de cada objeto das Mibs
void updateMibObjectValue(){

	const long minute = 60;
	const long hour = minute * 60; //3600
	const long day = hour * 60; //216000
	const double MB = 1024 * 1024; //1048576

	struct sysinfo sys_info;
		if(sysinfo(&sys_info) != 0)
		    perror("sys_info");

//valores de cada objeto de ccnSystem
//	snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "%ddays %dhours %dmins", sys_info.uptime/3600, sys_info.uptime%3600/60, sys_info.uptime%60);
//		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld days, %ld:%02ld:%02ld\n", sys_info.uptime / day, (sys_info.uptime % day) / hour,  (sys_info.uptime % day) / minute, sys_info.uptime % minute);
//		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld days, %ld:%02ld:%02ld\n", sys_info.uptime / day, sys_info.uptime / 3600, ((sys_info.uptime - (3600 * (sys_info.uptime / 3600))/60; (((sys_info.uptime - (3600 * (sys_info.uptime / 3600))/60) - (((sys_info.uptime - (3600 * (sys_info.uptime / 3600))/60);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_UPTIME], 50, "UPTIME: %ld seconds", sys_info.uptime);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_LOADS], 50, "LOADS: %d", sys_info.loads);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALRAM], 50, "TOTAL RAM: %d", sys_info.totalram);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREERAM], 50, "FREE RAM: %d", sys_info.freeram);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_SHAREDRAM], 50, "SHARED RAM: %d", sys_info.sharedram);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_BUFFERRAM], 50, "BUFFER RAM: %d", sys_info.bufferram);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALSWAP], 50, "TOTAL SWAP: %d", sys_info.totalswap);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREESWAP], 50, "FREE SWAP: %d", sys_info.freeswap);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_PROCS], 50, "PROCS: %d", sys_info.procs);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_TOTALHIGH], 50, "TOTAL HIGH: %d", sys_info.totalhigh);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_FREELHIGH], 50, "FREE HIGH: %d", sys_info.freehigh);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_MEMUNIT], 50, "MEM UNIT: %d", sys_info.mem_unit);
		snprintf(ccnMibSystemObjectValue[CCN_SYSTEM_OBJECT_CHARF], 50, "CHAR_F: %d", sys_info._f);

	//leitura de arquivos com conteudo de cada objeto de ccndStatus/contentItems

		char * hostname = getenv("NE_NAME");

		char path_ciaccessioned0[100];
		sprintf(path_ciaccessioned0, "/home/user/ccndStatus-ObjectValues/%s.content_items.accessioned.0", hostname);
		FILE *file_ciaccessioned0;
		file_ciaccessioned0 = fopen(path_ciaccessioned0, "r");
		char object_ciaccessioned0[100];

		char path_ciduplicate0[100];
		sprintf(path_ciduplicate0, "/home/user/ccndStatus-ObjectValues/%s.content_items.duplicate.0", hostname);
		FILE *file_ciduplicate0;
		file_ciduplicate0 = fopen(path_ciduplicate0, "r");
		char object_ciduplicate0[100];

		char path_cisent0[100];
		sprintf(path_cisent0, "/home/user/ccndStatus-ObjectValues/%s.content_items.sent.0", hostname);
		FILE *file_cisent0;
		file_cisent0 = fopen(path_cisent0, "r");
		char object_cisent0[100];

		char path_cisparse0[100];
		sprintf(path_cisparse0, "/home/user/ccndStatus-ObjectValues/%s.content_items.sparse.0", hostname);
		FILE *file_cisparse0;
		file_cisparse0 = fopen(path_cisparse0, "r");
		char object_cisparse0[100];

		char path_cistale0[100];
		sprintf(path_cistale0, "/home/user/ccndStatus-ObjectValues/%s.content_items.stale.0", hostname);
		FILE *file_cistale0;
		file_cistale0 = fopen(path_cistale0, "r");
		char object_cistale0[100];

		char path_cistored0[100];
		sprintf(path_cistored0, "/home/user/ccndStatus-ObjectValues/%s.content_items.stored.0", hostname);
		FILE *file_cistored0;
		file_cistored0 = fopen(path_cistored0, "r");
		char object_cistored0[100];

		char path_cihostname0[100];
		sprintf(path_cihostname0, "/home/user/ccndStatus-ObjectValues/%s.content_items.hostname.0", hostname);
		FILE *file_cihostname0;
		file_cihostname0 = fopen(path_cihostname0, "r");
		char object_cihostname0[100];

		char path_citime0[100];
		sprintf(path_citime0, "/home/user/ccndStatus-ObjectValues/%s.content_items.time.0", hostname);
		FILE *file_citime0;
		file_citime0 = fopen(path_citime0, "r");
		char object_citime0[100];

	//valores de cada objeto de ccndStatus/contentItems
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIACCESSIONED] = strdup (fgets (object_ciaccessioned0, sizeof(object_ciaccessioned0), file_ciaccessioned0)); fclose(file_ciaccessioned0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIDUPLICATE] = strdup (fgets (object_ciduplicate0, sizeof(object_ciduplicate0), file_ciduplicate0)); fclose(file_ciduplicate0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISENT] = strdup (fgets (object_cisent0, sizeof(object_cisent0), file_cisent0)); fclose(file_cisent0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISPARSE] = strdup (fgets (object_cisparse0, sizeof(object_cisparse0), file_cisparse0)); fclose(file_cisparse0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTALE] = strdup (fgets (object_cistale0, sizeof(object_cistale0), file_cistale0)); fclose(file_cistale0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CISTORED] = strdup (fgets (object_cistored0, sizeof(object_cistored0), file_cistored0)); fclose(file_cistored0);
	    ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CIHOST] = strdup (fgets (object_cihostname0, sizeof(object_cihostname0), file_cihostname0)); fclose(file_cihostname0);
	   	ccnMibStatusContentItemsObjectValue[CCN_STATUS_CONTENT_ITEMS_OBJECT_CITIMESTAMP] = strdup (fgets (object_citime0, sizeof(object_citime0), file_citime0)); fclose(file_citime0);

	//leitura de arquivos com conteudo de cada objeto de ccndStatus/interests

	   	char path_inames0[100];
	   	sprintf(path_inames0, "/home/user/ccndStatus-ObjectValues/%s.interests.names.0", hostname);
	   	FILE *file_inames0;
	   	file_inames0 = fopen(path_inames0, "r");
	   	char object_inames0[100];

	   	char path_inoted0[100];
	   	sprintf(path_inoted0, "/home/user/ccndStatus-ObjectValues/%s.interests.noted.0", hostname);
	   	FILE *file_inoted0;
	   	file_inoted0 = fopen(path_inoted0, "r");
	   	char object_inoted0[100];

	   	char path_ipending0[100];
	   	sprintf(path_ipending0, "/home/user/ccndStatus-ObjectValues/%s.interests.pending.0", hostname);
	   	FILE *file_ipending0;
	   	file_ipending0 = fopen(path_ipending0, "r");
	   	char object_ipending0[100];

	   	char path_ipropagating0[100];
	   	sprintf(path_ipropagating0, "/home/user/ccndStatus-ObjectValues/%s.interests.propagating.0", hostname);
	   	FILE *file_ipropagating0;
	   	file_ipropagating0 = fopen(path_ipropagating0, "r");
	   	char object_ipropagating0[100];

	   	char path_ihostname0[100];
	   	sprintf(path_ihostname0, "/home/user/ccndStatus-ObjectValues/%s.interests.hostname.0", hostname);
	   	FILE *file_ihostname0;
	   	file_ihostname0 = fopen(path_ihostname0, "r");
	   	char object_ihostname0[100];

	   	char path_itime0[100];
	   	sprintf(path_itime0, "/home/user/ccndStatus-ObjectValues/%s.interests.time.0", hostname);
	   	FILE *file_itime0;
	   	file_itime0 = fopen(path_itime0, "r");
	   	char object_itime0[100];

	//valores de cada objeto de ccndStatus/interests
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_INAMES] = strdup (fgets (object_inames0, sizeof(object_inames0), file_inames0)); fclose(file_inames0);
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_INOTED] = strdup (fgets (object_inoted0, sizeof(object_inoted0), file_inoted0)); fclose(file_inoted0);
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IPENDING] = strdup (fgets (object_ipending0, sizeof(object_ipending0), file_ipending0)); fclose(file_ipending0);
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IPROPAGATING] = strdup (fgets (object_ipropagating0, sizeof(object_ipropagating0), file_ipropagating0)); fclose(file_ipropagating0);
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_IHOST] = strdup (fgets (object_ihostname0, sizeof(object_ihostname0), file_ihostname0)); fclose(file_ihostname0);
	   	ccnMibStatusInterestsObjectValue[CCN_STATUS_INTERESTS_OBJECT_ITIMESTAMP] = strdup (fgets (object_itime0, sizeof(object_itime0), file_itime0)); fclose(file_itime0);

	//leitura de arquivos com conteudo de cada objeto de ccndStatus/interestsTotals

	   	char path_itaccepted0[100];
	 	sprintf(path_itaccepted0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.accepted.0", hostname);
	   	FILE *file_itaccepted0;
	   	file_itaccepted0 = fopen(path_itaccepted0, "r");
	   	char object_itaccepted0[100];

	   	char path_itdropped0[100];
	   	sprintf(path_itdropped0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.dropped.0", hostname);
	   	FILE *file_itdropped0;
	   	file_itdropped0 = fopen(path_itdropped0, "r");
	   	char object_itdropped0[100];

	   	char path_itsent0[100];
	   	sprintf(path_itsent0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.sent.0", hostname);
	   	FILE *file_itsent0;
	   	file_itsent0 = fopen(path_itsent0, "r");
	   	char object_itsent0[100];

	   	char path_itstuffed0[100];
	   	sprintf(path_itstuffed0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.stuffed.0", hostname);
	   	FILE *file_itstuffed0;
	   	file_itstuffed0 = fopen(path_itstuffed0, "r");
	   	char object_itstuffed0[100];

	   	char path_ithostname0[100];
	   	sprintf(path_ithostname0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.hostname.0", hostname);
	  	FILE *file_ithostname0;
		file_ithostname0 = fopen(path_ithostname0, "r");
	   	char object_ithostname0[100];

	   	char path_ittime0[100];
	   	sprintf(path_ittime0, "/home/user/ccndStatus-ObjectValues/%s.interest_totals.time.0", hostname);
	   	FILE *file_ittime0;
	   	file_ittime0 = fopen(path_ittime0, "r");
	   	char object_ittime0[100];

	//valores de cada objeto de ccndStatus/interestsTotals
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITACCEPTED] = strdup (fgets (object_itaccepted0, sizeof(object_itaccepted0), file_itaccepted0)); fclose(file_itaccepted0);
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITDROPPED] = strdup (fgets (object_itdropped0, sizeof(object_itdropped0), file_itdropped0)); fclose(file_itdropped0);
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSENT] = strdup (fgets (object_itsent0, sizeof(object_itsent0), file_itsent0)); fclose(file_itsent0);
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITSTUFFED] = strdup (fgets (object_itstuffed0, sizeof(object_itstuffed0), file_itstuffed0)); fclose(file_itstuffed0);
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITHOST] = strdup (fgets (object_ithostname0, sizeof(object_ithostname0), file_ithostname0)); fclose(file_ithostname0);
	   	ccnMibStatusInterestTotalsObjectValue[CCN_STATUS_INTEREST_TOTALS_OBJECT_ITTIMESTAMP] = strdup (fgets (object_ittime0, sizeof(object_ittime0), file_ittime0)); fclose(file_ittime0);

	//leitura de arquivos com conteudo de cada objeto de ccndStatus/faces

	   	char path_fface0[100];
	    sprintf(path_fface0, "/home/user/ccndStatus-ObjectValues/%s.faces.face.0", hostname);
	   	FILE *file_fface0;
	   	file_fface0 = fopen(path_fface0, "r");
	   	char object_fface0[100];

	   	if (file_fface0 == NULL) {
	   	file_fface0 = fopen(path_fface0, "w+");
	   	fprintf(file_fface0,"face0=NULL\n");
	   	rewind(file_fface0);
	   	}

	   	char path_fface1[100];
	    sprintf(path_fface1, "/home/user/ccndStatus-ObjectValues/%s.faces.face.1", hostname);
	   	FILE *file_fface1;
	   	file_fface1 = fopen(path_fface1, "r");
	   	char object_fface1[100];

	   	if (file_fface1 == NULL) {
	   	file_fface1 = fopen(path_fface1, "w+");
	   	fprintf(file_fface1,"face1=NULL\n");
	   	rewind(file_fface1);
	   	}

	   	char path_fface2[100];
	    sprintf(path_fface2, "/home/user/ccndStatus-ObjectValues/%s.faces.face.2", hostname);
	   	FILE *file_fface2;
	   	file_fface2 = fopen(path_fface2, "r");
	   	char object_fface2[100];

	   	if (file_fface2 == NULL) {
	   	file_fface2 = fopen(path_fface2, "w+");
	   	fprintf(file_fface2,"face2=NULL\n");
	   	rewind(file_fface2);
	   	}

	   	char path_fface3[100];
	    sprintf(path_fface3, "/home/user/ccndStatus-ObjectValues/%s.faces.face.3", hostname);
	   	FILE *file_fface3;
	   	file_fface3 = fopen(path_fface3, "r");
	   	char object_fface3[100];

	   	if (file_fface3 == NULL) {
	   	file_fface3 = fopen(path_fface3, "w+");
	   	fprintf(file_fface3,"face3=NULL\n");
	   	rewind(file_fface3);
	   	}

	   	char path_fface4[100];
	    sprintf(path_fface4, "/home/user/ccndStatus-ObjectValues/%s.faces.face.4", hostname);
	   	FILE *file_fface4;
	   	file_fface4 = fopen(path_fface4, "r");
	   	char object_fface4[100];

	   	if (file_fface4 == NULL) {
	   	file_fface4 = fopen(path_fface4, "w+");
	   	fprintf(file_fface4,"face4=NULL\n");
	   	rewind(file_fface4);
	   	}

	   	char path_fface5[100];
	    sprintf(path_fface5, "/home/user/ccndStatus-ObjectValues/%s.faces.face.5", hostname);
	   	FILE *file_fface5;
	   	file_fface5 = fopen(path_fface5, "r");
	   	char object_fface5[100];

	   	if (file_fface5 == NULL) {
	   	file_fface5 = fopen(path_fface5, "w+");
	   	fprintf(file_fface5,"face5=NULL\n");
	   	rewind(file_fface5);
	   	}

	   	char path_fface6[100];
	    sprintf(path_fface6, "/home/user/ccndStatus-ObjectValues/%s.faces.face.6", hostname);
	   	FILE *file_fface6;
	   	file_fface6 = fopen(path_fface6, "r");
	   	char object_fface6[100];

	   	if (file_fface6 == NULL) {
	   	file_fface6 = fopen(path_fface6, "w+");
	   	fprintf(file_fface6,"face6=NULL\n");
	   	rewind(file_fface6);
	   	}

	   	char path_fface7[100];
	    sprintf(path_fface7, "/home/user/ccndStatus-ObjectValues/%s.faces.face.7", hostname);
	   	FILE *file_fface7;
	   	file_fface7 = fopen(path_fface7, "r");
	   	char object_fface7[100];

	   	if (file_fface7 == NULL) {
	   	file_fface7 = fopen(path_fface7, "w+");
	   	fprintf(file_fface7,"face7=NULL\n");
	   	rewind(file_fface7);
	   	}

	   	char path_fface8[100];
	    sprintf(path_fface8, "/home/user/ccndStatus-ObjectValues/%s.faces.face.8", hostname);
	   	FILE *file_fface8;
	   	file_fface8 = fopen(path_fface8, "r");
	   	char object_fface8[100];

	   	if (file_fface8 == NULL) {
	   	file_fface8 = fopen(path_fface8, "w+");
	   	fprintf(file_fface8,"face8=NULL\n");
	   	rewind(file_fface8);
	   	}

	   	char path_fface9[100];
	    sprintf(path_fface9, "/home/user/ccndStatus-ObjectValues/%s.faces.face.9", hostname);
	   	FILE *file_fface9;
	   	file_fface9 = fopen(path_fface9, "r");
	   	char object_fface9[100];

	   	if (file_fface9 == NULL) {
	   	file_fface9 = fopen(path_fface9, "w+");
	   	fprintf(file_fface9,"face9=NULL\n");
	   	rewind(file_fface9);
	   	}

	   	char path_fface10[100];
	    sprintf(path_fface10, "/home/user/ccndStatus-ObjectValues/%s.faces.face.10", hostname);
	   	FILE *file_fface10;
	   	file_fface10 = fopen(path_fface10, "r");
	   	char object_fface10[100];

	   	if (file_fface10 == NULL) {
	   	file_fface10 = fopen(path_fface10, "w+");
	   	fprintf(file_fface10,"face10=NULL\n");
	   	rewind(file_fface10);
	   	}

	   	char path_fface11[100];
	    sprintf(path_fface11, "/home/user/ccndStatus-ObjectValues/%s.faces.face.11", hostname);
	   	FILE *file_fface11;
	   	file_fface11 = fopen(path_fface11, "r");
	   	char object_fface11[100];

	   	if (file_fface11 == NULL) {
	   	file_fface11 = fopen(path_fface11, "w+");
	   	fprintf(file_fface11,"face11=NULL\n");
	   	rewind(file_fface11);
	   	}

	   	char path_fface12[100];
	    sprintf(path_fface12, "/home/user/ccndStatus-ObjectValues/%s.faces.face.12", hostname);
	   	FILE *file_fface12;
	   	file_fface12 = fopen(path_fface12, "r");
	   	char object_fface12[100];

	   	if (file_fface12 == NULL) {
	   	file_fface12 = fopen(path_fface12, "w+");
	   	fprintf(file_fface12,"face12=NULL\n");
	   	rewind(file_fface12);
	   	}

	   	char path_fface13[100];
	    sprintf(path_fface13, "/home/user/ccndStatus-ObjectValues/%s.faces.face.13", hostname);
	   	FILE *file_fface13;
	   	file_fface13 = fopen(path_fface13, "r");
	   	char object_fface13[100];

	   	if (file_fface13 == NULL) {
	   	file_fface13 = fopen(path_fface13, "w+");
	   	fprintf(file_fface13,"face13=NULL\n");
	   	rewind(file_fface13);
	   	}

	   	char path_fflags0[100];
	   	sprintf(path_fflags0, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.0", hostname);
	   	FILE *file_fflags0;
	   	file_fflags0 = fopen(path_fflags0, "r");
	   	char object_fflags0[100];

	   	if (file_fflags0 == NULL) {
	   	file_fflags0 = fopen(path_fflags0, "w+");
	   	fprintf(file_fflags0,"flags0=NULL\n");
	   	rewind(file_fflags0);
	   	}

	   	char path_fflags1[100];
	   	sprintf(path_fflags1, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.1", hostname);
	   	FILE *file_fflags1;
	   	file_fflags1 = fopen(path_fflags1, "r");
	   	char object_fflags1[100];

	   	if (file_fflags1 == NULL) {
	   	file_fflags1 = fopen(path_fflags1, "w+");
	   	fprintf(file_fflags1,"flags1=NULL\n");
	   	rewind(file_fflags1);
	   	}

	   	char path_fflags2[100];
	   	sprintf(path_fflags2, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.2", hostname);
	   	FILE *file_fflags2;
	   	file_fflags2 = fopen(path_fflags2, "r");
	   	char object_fflags2[100];

	   	if (file_fflags2 == NULL) {
	   	file_fflags2 = fopen(path_fflags2, "w+");
	   	fprintf(file_fflags2,"flags2=NULL\n");
	   	rewind(file_fflags2);
	   	}

	   	char path_fflags3[100];
	   	sprintf(path_fflags3, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.3", hostname);
	   	FILE *file_fflags3;
	   	file_fflags3 = fopen(path_fflags3, "r");
	   	char object_fflags3[100];

	   	if (file_fflags3 == NULL) {
	   	file_fflags3 = fopen(path_fflags3, "w+");
	   	fprintf(file_fflags3,"flags3=NULL\n");
	   	rewind(file_fflags3);
	   	}

	   	char path_fflags4[100];
	   	sprintf(path_fflags4, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.4", hostname);
	   	FILE *file_fflags4;
	   	file_fflags4 = fopen(path_fflags4, "r");
	   	char object_fflags4[100];

	   	if (file_fflags4 == NULL) {
	   	file_fflags4 = fopen(path_fflags4, "w+");
	   	fprintf(file_fflags4,"flags4=NULL\n");
	   	rewind(file_fflags4);
	   	}

	   	char path_fflags5[100];
	   	sprintf(path_fflags5, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.5", hostname);
	   	FILE *file_fflags5;
	   	file_fflags5 = fopen(path_fflags5, "r");
	   	char object_fflags5[100];

	   	if (file_fflags5 == NULL) {
	   	file_fflags5 = fopen(path_fflags5, "w+");
	   	fprintf(file_fflags5,"flags5=NULL\n");
	   	rewind(file_fflags5);
	   	}

	   	char path_fflags6[100];
	   	sprintf(path_fflags6, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.6", hostname);
	   	FILE *file_fflags6;
	   	file_fflags6 = fopen(path_fflags6, "r");
	   	char object_fflags6[100];

	   	if (file_fflags6 == NULL) {
	   	file_fflags6 = fopen(path_fflags6, "w+");
	   	fprintf(file_fflags6,"flags6=NULL\n");
	   	rewind(file_fflags6);
	   	}

	   	char path_fflags7[100];
	   	sprintf(path_fflags7, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.7", hostname);
	   	FILE *file_fflags7;
	   	file_fflags7 = fopen(path_fflags7, "r");
	   	char object_fflags7[100];

	   	if (file_fflags7 == NULL) {
	   	file_fflags7 = fopen(path_fflags7, "w+");
	   	fprintf(file_fflags7,"flags7=NULL\n");
	   	rewind(file_fflags7);
	   	}

	   	char path_fflags8[100];
	   	sprintf(path_fflags8, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.8", hostname);
	   	FILE *file_fflags8;
	   	file_fflags8 = fopen(path_fflags8, "r");
	   	char object_fflags8[100];

	   	if (file_fflags8 == NULL) {
	   	file_fflags8 = fopen(path_fflags8, "w+");
	   	fprintf(file_fflags8,"flags8=NULL\n");
	   	rewind(file_fflags8);
	   	}

	   	char path_fflags9[100];
	   	sprintf(path_fflags9, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.9", hostname);
	   	FILE *file_fflags9;
	   	file_fflags9 = fopen(path_fflags9, "r");
	   	char object_fflags9[100];

	   	if (file_fflags9 == NULL) {
	   	file_fflags9 = fopen(path_fflags9, "w+");
	   	fprintf(file_fflags9,"flags9=NULL\n");
	   	rewind(file_fflags9);
	   	}

	   	char path_fflags10[100];
	   	sprintf(path_fflags10, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.10", hostname);
	   	FILE *file_fflags10;
	   	file_fflags10 = fopen(path_fflags10, "r");
	   	char object_fflags10[100];

	   	if (file_fflags10 == NULL) {
	   	file_fflags10 = fopen(path_fflags10, "w+");
	   	fprintf(file_fflags10,"flags10=NULL\n");
	   	rewind(file_fflags10);
	   	}

	   	char path_fflags11[100];
	   	sprintf(path_fflags11, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.11", hostname);
	   	FILE *file_fflags11;
	   	file_fflags11 = fopen(path_fflags11, "r");
	   	char object_fflags11[100];

	   	if (file_fflags11 == NULL) {
	   	file_fflags11 = fopen(path_fflags11, "w+");
	   	fprintf(file_fflags11,"flags11=NULL\n");
	   	rewind(file_fflags11);
	   	}

	   	char path_fflags12[100];
	   	sprintf(path_fflags12, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.12", hostname);
	   	FILE *file_fflags12;
	   	file_fflags12 = fopen(path_fflags12, "r");
	   	char object_fflags12[100];

	   	if (file_fflags12 == NULL) {
	   	file_fflags12 = fopen(path_fflags12, "w+");
	   	fprintf(file_fflags12,"flags12=NULL\n");
	   	rewind(file_fflags12);
	   	}

	   	char path_fflags13[100];
	   	sprintf(path_fflags13, "/home/user/ccndStatus-ObjectValues/%s.faces.flags.13", hostname);
	   	FILE *file_fflags13;
	   	file_fflags13 = fopen(path_fflags13, "r");
	   	char object_fflags13[100];

	   	if (file_fflags13 == NULL) {
	   	file_fflags13 = fopen(path_fflags13, "w+");
	   	fprintf(file_fflags13,"flags13=NULL\n");
	   	rewind(file_fflags13);
	   	}

	   	char path_flocal0[100];
	   	sprintf(path_flocal0, "/home/user/ccndStatus-ObjectValues/%s.faces.local.0", hostname);
	   	FILE *file_flocal0;
	   	file_flocal0 = fopen(path_flocal0, "r");
	   	char object_flocal0[100];

	  	if (file_flocal0 == NULL) {
	   	file_flocal0 = fopen(path_flocal0, "w+");
	   	fprintf(file_flocal0,"local0=NULL\n");
	   	rewind(file_flocal0);
	   	}

	   	char path_flocal1[100];
	   	sprintf(path_flocal1, "/home/user/ccndStatus-ObjectValues/%s.faces.local.1", hostname);
	   	FILE *file_flocal1;
	   	file_flocal1 = fopen(path_flocal1, "r");
	   	char object_flocal1[100];

	  	if (file_flocal1 == NULL) {
	   	file_flocal1 = fopen(path_flocal1, "w+");
	   	fprintf(file_flocal1,"local1=NULL\n");
	   	rewind(file_flocal1);
	   	}

	    char path_flocal2[100];
	   	sprintf(path_flocal2, "/home/user/ccndStatus-ObjectValues/%s.faces.local.2", hostname);
	   	FILE *file_flocal2;
	   	file_flocal2 = fopen(path_flocal2, "r");
	   	char object_flocal2[100];

	  	if (file_flocal2 == NULL) {
	   	file_flocal2 = fopen(path_flocal2, "w+");
	   	fprintf(file_flocal2,"local2=NULL\n");
	   	rewind(file_flocal2);
	   	}

	   	char path_flocal3[100];
	   	sprintf(path_flocal3, "/home/user/ccndStatus-ObjectValues/%s.faces.local.3", hostname);
	   	FILE *file_flocal3;
	   	file_flocal3 = fopen(path_flocal3, "r");
	   	char object_flocal3[100];

	  	if (file_flocal3 == NULL) {
	   	file_flocal3 = fopen(path_flocal3, "w+");
	   	fprintf(file_flocal3,"local3=NULL\n");
	   	rewind(file_flocal3);
	   	}

	   	char path_flocal4[100];
	   	sprintf(path_flocal4, "/home/user/ccndStatus-ObjectValues/%s.faces.local.4", hostname);
	   	FILE *file_flocal4;
	   	file_flocal4 = fopen(path_flocal4, "r");
	   	char object_flocal4[100];

	  	if (file_flocal4 == NULL) {
	   	file_flocal4 = fopen(path_flocal4, "w+");
	   	fprintf(file_flocal4,"local4=NULL\n");
	   	rewind(file_flocal4);
	   	}

	   	char path_flocal5[100];
	   	sprintf(path_flocal5, "/home/user/ccndStatus-ObjectValues/%s.faces.local.5", hostname);
	   	FILE *file_flocal5;
	   	file_flocal5 = fopen(path_flocal5, "r");
	   	char object_flocal5[100];

	  	if (file_flocal5 == NULL) {
	   	file_flocal5 = fopen(path_flocal5, "w+");
	   	fprintf(file_flocal5,"local5=NULL\n");
	   	rewind(file_flocal5);
	   	}

	   	char path_flocal6[100];
	   	sprintf(path_flocal6, "/home/user/ccndStatus-ObjectValues/%s.faces.local.6", hostname);
	   	FILE *file_flocal6;
	   	file_flocal6 = fopen(path_flocal6, "r");
	   	char object_flocal6[100];

	  	if (file_flocal6 == NULL) {
	   	file_flocal6 = fopen(path_flocal6, "w+");
	   	fprintf(file_flocal6,"local6=NULL\n");
	   	rewind(file_flocal6);
	   	}

	   	char path_flocal7[100];
	   	sprintf(path_flocal7, "/home/user/ccndStatus-ObjectValues/%s.faces.local.7", hostname);
	    FILE *file_flocal7;
	   	file_flocal7 = fopen(path_flocal7, "r");
	   	char object_flocal7[100];

	  	if (file_flocal7 == NULL) {
	   	file_flocal7 = fopen(path_flocal7, "w+");
	   	fprintf(file_flocal7,"local7=NULL\n");
	   	rewind(file_flocal7);
	   	}

	   	char path_flocal8[100];
	   	sprintf(path_flocal8, "/home/user/ccndStatus-ObjectValues/%s.faces.local.8", hostname);
	   	FILE *file_flocal8;
	   	file_flocal8 = fopen(path_flocal8, "r");
	   	char object_flocal8[100];

	  	if (file_flocal8 == NULL) {
	   	file_flocal8 = fopen(path_flocal8, "w+");
	   	fprintf(file_flocal8,"local8=NULL\n");
	   	rewind(file_flocal8);
	   	}

	   	char path_flocal9[100];
	   	sprintf(path_flocal9, "/home/user/ccndStatus-ObjectValues/%s.faces.local.9", hostname);
	   	FILE *file_flocal9;
	   	file_flocal9 = fopen(path_flocal9, "r");
	   	char object_flocal9[100];

	  	if (file_flocal9 == NULL) {
	   	file_flocal9 = fopen(path_flocal9, "w+");
	   	fprintf(file_flocal9,"local9=NULL\n");
	   	rewind(file_flocal9);
	   	}

	   	char path_flocal10[100];
	   	sprintf(path_flocal10, "/home/user/ccndStatus-ObjectValues/%s.faces.local.10", hostname);
	   	FILE *file_flocal10;
	   	file_flocal10 = fopen(path_flocal10, "r");
	   	char object_flocal10[100];

	  	if (file_flocal10 == NULL) {
	   	file_flocal10 = fopen(path_flocal10, "w+");
	   	fprintf(file_flocal10,"local10=NULL\n");
	   	rewind(file_flocal10);
	   	}

	   	char path_flocal11[100];
	   	sprintf(path_flocal11, "/home/user/ccndStatus-ObjectValues/%s.faces.local.11", hostname);
	   	FILE *file_flocal11;
	   	file_flocal11 = fopen(path_flocal11, "r");
	   	char object_flocal11[100];

	  	if (file_flocal11 == NULL) {
	   	file_flocal11 = fopen(path_flocal11, "w+");
	   	fprintf(file_flocal11,"local11=NULL\n");
	   	rewind(file_flocal11);
	   	}

	   	char path_flocal12[100];
	   	sprintf(path_flocal12, "/home/user/ccndStatus-ObjectValues/%s.faces.local.12", hostname);
	   	FILE *file_flocal12;
	   	file_flocal12 = fopen(path_flocal12, "r");
	   	char object_flocal12[100];

	  	if (file_flocal12 == NULL) {
	   	file_flocal12 = fopen(path_flocal12, "w+");
	   	fprintf(file_flocal12,"local12=NULL\n");
	   	rewind(file_flocal12);
	   	}

	   	char path_flocal13[100];
	   	sprintf(path_flocal13, "/home/user/ccndStatus-ObjectValues/%s.faces.local.13", hostname);
	   	FILE *file_flocal13;
	   	file_flocal13 = fopen(path_flocal13, "r");
	   	char object_flocal13[100];

	   	if (file_flocal13 == NULL) {
	   	file_flocal13 = fopen(path_flocal13, "w+");
	   	fprintf(file_flocal13,"local13=NULL\n");
	   	rewind(file_flocal13);
	   	}

	   	char path_fpending0[100];
	   	sprintf(path_fpending0, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.0", hostname);
	   	FILE *file_fpending0;
	   	file_fpending0 = fopen(path_fpending0, "r");
	   	char object_fpending0[100];

	  	if (file_fpending0 == NULL) {
	   	file_fpending0 = fopen(path_fpending0, "w+");
	   	fprintf(file_fpending0,"pending0=NULL\n");
	   	rewind(file_fpending0);
	   	}

	   	char path_fpending1[100];
	   	sprintf(path_fpending1, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.1", hostname);
	   	FILE *file_fpending1;
	   	file_fpending1 = fopen(path_fpending1, "r");
	   	char object_fpending1[100];

	 	if (file_fpending1 == NULL) {
	   	file_fpending1 = fopen(path_fpending1, "w+");
	   	fprintf(file_fpending1,"pending1=NULL\n");
	   	rewind(file_fpending1);
	   	}

	   	char path_fpending2[100];
	   	sprintf(path_fpending2, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.2", hostname);
	   	FILE *file_fpending2;
	   	file_fpending2 = fopen(path_fpending2, "r");
	   	char object_fpending2[100];

	 	if (file_fpending2 == NULL) {
	   	file_fpending2 = fopen(path_fpending2, "w+");
	   	fprintf(file_fpending2,"pending2=NULL\n");
	   	rewind(file_fpending2);
	   	}

	   	char path_fpending3[100];
	   	sprintf(path_fpending3, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.3", hostname);
	   	FILE *file_fpending3;
	   	file_fpending3 = fopen(path_fpending3, "r");
	   	char object_fpending3[100];

	 	if (file_fpending3 == NULL) {
	   	file_fpending3 = fopen(path_fpending3, "w+");
	   	fprintf(file_fpending3,"pending3=NULL\n");
	   	rewind(file_fpending3);
	   	}

	   	char path_fpending4[100];
	   	sprintf(path_fpending4, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.4", hostname);
	   	FILE *file_fpending4;
	   	file_fpending4 = fopen(path_fpending4, "r");
	   	char object_fpending4[100];

	 	if (file_fpending4 == NULL) {
	   	file_fpending4 = fopen(path_fpending4, "w+");
	   	fprintf(file_fpending4,"pending4=NULL\n");
	   	rewind(file_fpending4);
	   	}

	   	char path_fpending5[100];
	   	sprintf(path_fpending5, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.5", hostname);
	   	FILE *file_fpending5;
	   	file_fpending5 = fopen(path_fpending5, "r");
	   	char object_fpending5[100];

	 	if (file_fpending5 == NULL) {
	   	file_fpending5 = fopen(path_fpending5, "w+");
	   	fprintf(file_fpending5,"pending5=NULL\n");
	   	rewind(file_fpending5);
	   	}

	   	char path_fpending6[100];
	   	sprintf(path_fpending6, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.6", hostname);
	   	FILE *file_fpending6;
	   	file_fpending6 = fopen(path_fpending6, "r");
	   	char object_fpending6[100];

	 	if (file_fpending6 == NULL) {
	   	file_fpending6 = fopen(path_fpending6, "w+");
	   	fprintf(file_fpending6,"pending6=NULL\n");
	   	rewind(file_fpending6);
	   	}

	   	char path_fpending7[100];
	   	sprintf(path_fpending7, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.7", hostname);
	   	FILE *file_fpending7;
	   	file_fpending7 = fopen(path_fpending7, "r");
	   	char object_fpending7[100];

	 	if (file_fpending7 == NULL) {
	   	file_fpending7 = fopen(path_fpending7, "w+");
	   	fprintf(file_fpending7,"pending7=NULL\n");
	   	rewind(file_fpending7);
	   	}

	   	char path_fpending8[100];
	   	sprintf(path_fpending8, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.8", hostname);
	   	FILE *file_fpending8;
	   	file_fpending8 = fopen(path_fpending8, "r");
	   	char object_fpending8[100];

	 	if (file_fpending8 == NULL) {
	   	file_fpending8 = fopen(path_fpending8, "w+");
	   	fprintf(file_fpending8,"pending8=NULL\n");
	   	rewind(file_fpending8);
	   	}

	   	char path_fpending9[100];
	   	sprintf(path_fpending9, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.9", hostname);
	   	FILE *file_fpending9;
	   	file_fpending9 = fopen(path_fpending9, "r");
	   	char object_fpending9[100];

	 	if (file_fpending9 == NULL) {
	   	file_fpending9 = fopen(path_fpending9, "w+");
	   	fprintf(file_fpending9,"pending9=NULL\n");
	   	rewind(file_fpending9);
	   	}

	   	char path_fpending10[100];
	   	sprintf(path_fpending10, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.10", hostname);
	   	FILE *file_fpending10;
	   	file_fpending10 = fopen(path_fpending10, "r");
	   	char object_fpending10[100];

	 	if (file_fpending10 == NULL) {
	   	file_fpending10 = fopen(path_fpending10, "w+");
	   	fprintf(file_fpending10,"pending10=NULL\n");
	   	rewind(file_fpending10);
	   	}

	   	char path_fpending11[100];
	   	sprintf(path_fpending11, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.11", hostname);
	   	FILE *file_fpending11;
	   	file_fpending11 = fopen(path_fpending11, "r");
	   	char object_fpending11[100];

	 	if (file_fpending11 == NULL) {
	   	file_fpending11 = fopen(path_fpending11, "w+");
	   	fprintf(file_fpending11,"pending11=NULL\n");
	   	rewind(file_fpending11);
	   	}

	   	char path_fpending12[100];
	   	sprintf(path_fpending12, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.12", hostname);
	   	FILE *file_fpending12;
	   	file_fpending12 = fopen(path_fpending12, "r");
	   	char object_fpending12[100];

	 	if (file_fpending12 == NULL) {
	   	file_fpending12 = fopen(path_fpending12, "w+");
	   	fprintf(file_fpending12,"pending12=NULL\n");
	   	rewind(file_fpending12);
	   	}

	   	char path_fpending13[100];
	   	sprintf(path_fpending13, "/home/user/ccndStatus-ObjectValues/%s.faces.pending.13", hostname);
	   	FILE *file_fpending13;
	   	file_fpending13 = fopen(path_fpending13, "r");
	   	char object_fpending13[100];

	 	if (file_fpending13 == NULL) {
	   	file_fpending13 = fopen(path_fpending13, "w+");
	   	fprintf(file_fpending13,"pending13=NULL\n");
	   	rewind(file_fpending13);
	   	}

	   	char path_fremote0[100];
	   	sprintf(path_fremote0, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.0", hostname);
	   	FILE *file_fremote0;
	   	file_fremote0 = fopen(path_fremote0, "r");
	   	char object_fremote0[100];

	 	if (file_fremote0 == NULL) {
	   	file_fremote0 = fopen(path_fremote0, "w+");
	   	fprintf(file_fremote0,"fremote0=NULL\n");
	   	rewind(file_fremote0);
	   	}

	   	char path_fremote1[100];
	   	sprintf(path_fremote1, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.1", hostname);
	   	FILE *file_fremote1;
	   	file_fremote1 = fopen(path_fremote1, "r");
	   	char object_fremote1[100];

	 	if (file_fremote1 == NULL) {
	   	file_fremote1 = fopen(path_fremote1, "w+");
	   	fprintf(file_fremote1,"fremote1=NULL\n");
	   	rewind(file_fremote1);
	   	}

	   	char path_fremote2[100];
	   	sprintf(path_fremote2, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.2", hostname);
	   	FILE *file_fremote2;
	   	file_fremote2 = fopen(path_fremote2, "r");
	   	char object_fremote2[100];

	 	if (file_fremote2 == NULL) {
	   	file_fremote2 = fopen(path_fremote2, "w+");
	   	fprintf(file_fremote2,"fremote2=NULL\n");
	   	rewind(file_fremote2);
	   	}

	   	char path_fremote3[100];
	   	sprintf(path_fremote3, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.3", hostname);
	   	FILE *file_fremote3;
	   	file_fremote3 = fopen(path_fremote3, "r");
	   	char object_fremote3[100];

	 	if (file_fremote3 == NULL) {
	   	file_fremote3 = fopen(path_fremote3, "w+");
	   	fprintf(file_fremote3,"fremote3=NULL\n");
	   	rewind(file_fremote3);
	   	}

	   	char path_fremote4[100];
	   	sprintf(path_fremote4, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.4", hostname);
	   	FILE *file_fremote4;
	   	file_fremote4 = fopen(path_fremote4, "r");
	   	char object_fremote4[100];

	 	if (file_fremote4 == NULL) {
	   	file_fremote4 = fopen(path_fremote4, "w+");
	   	fprintf(file_fremote4,"fremote4=NULL\n");
	   	rewind(file_fremote4);
	   	}

	   	char path_fremote5[100];
	   	sprintf(path_fremote5, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.5", hostname);
	   	FILE *file_fremote5;
	   	file_fremote5 = fopen(path_fremote5, "r");
	   	char object_fremote5[100];

	 	if (file_fremote5 == NULL) {
	   	file_fremote5 = fopen(path_fremote5, "w+");
	   	fprintf(file_fremote5,"fremote5=NULL\n");
	   	rewind(file_fremote5);
	   	}

	   	char path_fremote6[100];
	   	sprintf(path_fremote6, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.6", hostname);
	   	FILE *file_fremote6;
	   	file_fremote6 = fopen(path_fremote6, "r");
	   	char object_fremote6[100];

	 	if (file_fremote6 == NULL) {
	   	file_fremote6 = fopen(path_fremote6, "w+");
	   	fprintf(file_fremote6,"fremote6=NULL\n");
	   	rewind(file_fremote6);
	   	}

	   	char path_fremote7[100];
	   	sprintf(path_fremote7, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.7", hostname);
	   	FILE *file_fremote7;
	   	file_fremote7 = fopen(path_fremote7, "r");
	   	char object_fremote7[100];

	 	if (file_fremote7 == NULL) {
	   	file_fremote7 = fopen(path_fremote7, "w+");
	   	fprintf(file_fremote7,"fremote7=NULL\n");
	   	rewind(file_fremote7);
	   	}

	   	char path_fremote8[100];
	   	sprintf(path_fremote8, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.8", hostname);
	   	FILE *file_fremote8;
	   	file_fremote8 = fopen(path_fremote8, "r");
	   	char object_fremote8[100];

	 	if (file_fremote8 == NULL) {
	   	file_fremote8 = fopen(path_fremote8, "w+");
	   	fprintf(file_fremote8,"fremote8=NULL\n");
	   	rewind(file_fremote8);
	   	}

	   	char path_fremote9[100];
	   	sprintf(path_fremote9, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.9", hostname);
	   	FILE *file_fremote9;
	   	file_fremote9 = fopen(path_fremote9, "r");
	   	char object_fremote9[100];

	 	if (file_fremote9 == NULL) {
	   	file_fremote9 = fopen(path_fremote9, "w+");
	   	fprintf(file_fremote9,"fremote9=NULL\n");
	   	rewind(file_fremote9);
	   	}

	   	char path_fremote10[100];
	   	sprintf(path_fremote10, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.10", hostname);
	   	FILE *file_fremote10;
	   	file_fremote10 = fopen(path_fremote10, "r");
	   	char object_fremote10[100];

	 	if (file_fremote10 == NULL) {
	   	file_fremote10 = fopen(path_fremote10, "w+");
	   	fprintf(file_fremote10,"fremote10=NULL\n");
	   	rewind(file_fremote10);
	   	}

	   	char path_fremote11[100];
	   	sprintf(path_fremote11, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.11", hostname);
	   	FILE *file_fremote11;
	   	file_fremote11 = fopen(path_fremote11, "r");
	   	char object_fremote11[100];

	 	if (file_fremote11 == NULL) {
	   	file_fremote11 = fopen(path_fremote11, "w+");
	   	fprintf(file_fremote11,"fremote11=NULL\n");
	   	rewind(file_fremote11);
	   	}

	   	char path_fremote12[100];
	   	sprintf(path_fremote12, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.12", hostname);
	   	FILE *file_fremote12;
	   	file_fremote12 = fopen(path_fremote12, "r");
	   	char object_fremote12[100];

	 	if (file_fremote12 == NULL) {
	   	file_fremote12 = fopen(path_fremote12, "w+");
	   	fprintf(file_fremote12,"fremote12=NULL\n");
	   	rewind(file_fremote12);
	   	}

	   	char path_fremote13[100];
	   	sprintf(path_fremote13, "/home/user/ccndStatus-ObjectValues/%s.faces.remote.13", hostname);
	   	FILE *file_fremote13;
	   	file_fremote13 = fopen(path_fremote13, "r");
	   	char object_fremote13[100];

	 	if (file_fremote13 == NULL) {
	   	file_fremote13 = fopen(path_fremote13, "w+");
	   	fprintf(file_fremote13,"fremote13=NULL\n");
	   	rewind(file_fremote13);
	   	}

	   	char path_fhostname0[100];
	   	sprintf(path_fhostname0, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.0", hostname);
	  	FILE *file_fhostname0;
		file_fhostname0 = fopen(path_fhostname0, "r");
	   	char object_fhostname0[100];

	 	if (file_fhostname0 == NULL) {
	   	file_fhostname0 = fopen(path_fhostname0, "w+");
	   	fprintf(file_fhostname0,"hostname0=NULL\n");
	   	rewind(file_fhostname0);
	   	}

	   	char path_fhostname1[100];
	   	sprintf(path_fhostname1, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.1", hostname);
	   	FILE *file_fhostname1;
	   	file_fhostname1 = fopen(path_fhostname1, "r");
	   	char object_fhostname1[100];

	 	if (file_fhostname1 == NULL) {
	   	file_fhostname1 = fopen(path_fhostname1, "w+");
	   	fprintf(file_fhostname1,"hostname1=NULL\n");
	   	rewind(file_fhostname1);
	   	}

	   	char path_fhostname2[100];
	   	sprintf(path_fhostname2, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.2", hostname);
	   	FILE *file_fhostname2;
	   	file_fhostname2 = fopen(path_fhostname2, "r");
	   	char object_fhostname2[100];

	 	if (file_fhostname2 == NULL) {
	   	file_fhostname2 = fopen(path_fhostname2, "w+");
	   	fprintf(file_fhostname2,"hostname2=NULL\n");
	   	rewind(file_fhostname2);
	   	}

	   	char path_fhostname3[100];
	   	sprintf(path_fhostname3, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.3", hostname);
	   	FILE *file_fhostname3;
	   	file_fhostname3 = fopen(path_fhostname3, "r");
	   	char object_fhostname3[100];

	 	if (file_fhostname3 == NULL) {
	   	file_fhostname3 = fopen(path_fhostname3, "w+");
	   	fprintf(file_fhostname3,"hostname3=NULL\n");
	   	rewind(file_fhostname3);
	   	}

	   	char path_fhostname4[100];
	   	sprintf(path_fhostname4, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.4", hostname);
	   	FILE *file_fhostname4;
	   	file_fhostname4 = fopen(path_fhostname4, "r");
	   	char object_fhostname4[100];

	 	if (file_fhostname4 == NULL) {
	   	file_fhostname4 = fopen(path_fhostname4, "w+");
	   	fprintf(file_fhostname4,"hostname4=NULL\n");
	   	rewind(file_fhostname4);
	   	}

	   	char path_fhostname5[100];
	   	sprintf(path_fhostname5, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.5", hostname);
	   	FILE *file_fhostname5;
	   	file_fhostname5 = fopen(path_fhostname5, "r");
	   	char object_fhostname5[100];

	 	if (file_fhostname5 == NULL) {
	   	file_fhostname5 = fopen(path_fhostname5, "w+");
	   	fprintf(file_fhostname5,"hostname5=NULL\n");
	   	rewind(file_fhostname5);
	   	}

	   	char path_fhostname6[100];
	   	sprintf(path_fhostname6, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.6", hostname);
	   	FILE *file_fhostname6;
	   	file_fhostname6 = fopen(path_fhostname6, "r");
	   	char object_fhostname6[100];

	 	if (file_fhostname6 == NULL) {
	   	file_fhostname6 = fopen(path_fhostname6, "w+");
	   	fprintf(file_fhostname6,"hostname6=NULL\n");
	   	rewind(file_fhostname6);
	   	}

	   	char path_fhostname7[100];
	   	sprintf(path_fhostname7, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.7", hostname);
	   	FILE *file_fhostname7;
	   	file_fhostname7 = fopen(path_fhostname7, "r");
	   	char object_fhostname7[100];

	 	if (file_fhostname7 == NULL) {
	   	file_fhostname7 = fopen(path_fhostname7, "w+");
	   	fprintf(file_fhostname7,"hostname7=NULL\n");
	   	rewind(file_fhostname7);
	   	}

	   	char path_fhostname8[100];
	   	sprintf(path_fhostname8, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.8", hostname);
	   	FILE *file_fhostname8;
	   	file_fhostname8 = fopen(path_fhostname8, "r");
	   	char object_fhostname8[100];

	 	if (file_fhostname8 == NULL) {
	   	file_fhostname8 = fopen(path_fhostname8, "w+");
	   	fprintf(file_fhostname8,"hostname8=NULL\n");
	   	rewind(file_fhostname8);
	   	}

	   	char path_fhostname9[100];
	   	sprintf(path_fhostname9, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.9", hostname);
	   	FILE *file_fhostname9;
	   	file_fhostname9 = fopen(path_fhostname9, "r");
	   	char object_fhostname9[100];

	 	if (file_fhostname9 == NULL) {
	   	file_fhostname9 = fopen(path_fhostname9, "w+");
	   	fprintf(file_fhostname9,"hostname9=NULL\n");
	   	rewind(file_fhostname9);
	   	}

	   	char path_fhostname10[100];
	   	sprintf(path_fhostname10, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.10", hostname);
	   	FILE *file_fhostname10;
	   	file_fhostname10 = fopen(path_fhostname10, "r");
	   	char object_fhostname10[100];

	 	if (file_fhostname10 == NULL) {
	   	file_fhostname10 = fopen(path_fhostname10, "w+");
	   	fprintf(file_fhostname10,"hostname10=NULL\n");
	   	rewind(file_fhostname10);
	   	}

	   	char path_fhostname11[100];
	   	sprintf(path_fhostname11, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.11", hostname);
	   	FILE *file_fhostname11;
	   	file_fhostname11 = fopen(path_fhostname11, "r");
	   	char object_fhostname11[100];

	 	if (file_fhostname11 == NULL) {
	   	file_fhostname11 = fopen(path_fhostname11, "w+");
	   	fprintf(file_fhostname11,"hostname11=NULL\n");
	   	rewind(file_fhostname11);
	   	}

	   	char path_fhostname12[100];
	   	sprintf(path_fhostname12, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.12", hostname);
	   	FILE *file_fhostname12;
	   	file_fhostname12 = fopen(path_fhostname12, "r");
	   	char object_fhostname12[100];

	 	if (file_fhostname12 == NULL) {
	   	file_fhostname12 = fopen(path_fhostname12, "w+");
	   	fprintf(file_fhostname12,"hostname12=NULL\n");
	   	rewind(file_fhostname12);
	   	}

	   	char path_fhostname13[100];
	   	sprintf(path_fhostname13, "/home/user/ccndStatus-ObjectValues/%s.faces.hostname.13", hostname);
	   	FILE *file_fhostname13;
	   	file_fhostname13 = fopen(path_fhostname13, "r");
	   	char object_fhostname13[100];

	 	if (file_fhostname13 == NULL) {
	   	file_fhostname13 = fopen(path_fhostname13, "w+");
	   	fprintf(file_fhostname13,"hostname13=NULL\n");
	   	rewind(file_fhostname13);
	   	}

	   	char path_ftime0[100];
	   	sprintf(path_ftime0, "/home/user/ccndStatus-ObjectValues/%s.faces.time.0", hostname);
	   	FILE *file_ftime0;
	   	file_ftime0 = fopen(path_ftime0, "r");
	   	char object_ftime0[100];

	 	if (file_ftime0 == NULL) {
	   	file_ftime0 = fopen(path_ftime0, "w+");
	   	fprintf(file_ftime0,"time0=NULL\n");
	   	rewind(file_ftime0);
	   	}

	   	char path_ftime1[100];
	   	sprintf(path_ftime1, "/home/user/ccndStatus-ObjectValues/%s.faces.time.1", hostname);
	   	FILE *file_ftime1;
	   	file_ftime1 = fopen(path_ftime1, "r");
	   	char object_ftime1[100];

	 	if (file_ftime1 == NULL) {
	   	file_ftime1 = fopen(path_ftime1, "w+");
	   	fprintf(file_ftime1,"time1=NULL\n");
	   	rewind(file_ftime1);
	   	}

	   	char path_ftime2[100];
	   	sprintf(path_ftime2, "/home/user/ccndStatus-ObjectValues/%s.faces.time.2", hostname);
	   	FILE *file_ftime2;
	   	file_ftime2 = fopen(path_ftime2, "r");
	   	char object_ftime2[100];

	 	if (file_ftime2 == NULL) {
	   	file_ftime2 = fopen(path_ftime2, "w+");
	   	fprintf(file_ftime2,"time2=NULL\n");
	   	rewind(file_ftime2);
	   	}

	   	char path_ftime3[100];
	   	sprintf(path_ftime3, "/home/user/ccndStatus-ObjectValues/%s.faces.time.3", hostname);
	   	FILE *file_ftime3;
	   	file_ftime3 = fopen(path_ftime3, "r");
	   	char object_ftime3[100];

	 	if (file_ftime3 == NULL) {
	   	file_ftime3 = fopen(path_ftime3, "w+");
	   	fprintf(file_ftime3,"time3=NULL\n");
	   	rewind(file_ftime3);
	   	}

	   	char path_ftime4[100];
	   	sprintf(path_ftime4, "/home/user/ccndStatus-ObjectValues/%s.faces.time.4", hostname);
	   	FILE *file_ftime4;
	   	file_ftime4 = fopen(path_ftime4, "r");
	   	char object_ftime4[100];

	 	if (file_ftime4 == NULL) {
	   	file_ftime4 = fopen(path_ftime4, "w+");
	   	fprintf(file_ftime4,"time4=NULL\n");
	   	rewind(file_ftime4);
	   	}

	   	char path_ftime5[100];
	   	sprintf(path_ftime5, "/home/user/ccndStatus-ObjectValues/%s.faces.time.5", hostname);
	   	FILE *file_ftime5;
	   	file_ftime5 = fopen(path_ftime5, "r");
	   	char object_ftime5[100];

	 	if (file_ftime5 == NULL) {
	   	file_ftime5 = fopen(path_ftime5, "w+");
	   	fprintf(file_ftime5,"time5=NULL\n");
	   	rewind(file_ftime5);
	   	}

	   	char path_ftime6[100];
	   	sprintf(path_ftime6, "/home/user/ccndStatus-ObjectValues/%s.faces.time.6", hostname);
	   	FILE *file_ftime6;
	   	file_ftime6 = fopen(path_ftime6, "r");
	   	char object_ftime6[100];

	 	if (file_ftime6 == NULL) {
	   	file_ftime6 = fopen(path_ftime6, "w+");
	   	fprintf(file_ftime6,"time6=NULL\n");
	   	rewind(file_ftime6);
	   	}

	   	char path_ftime7[100];
	   	sprintf(path_ftime7, "/home/user/ccndStatus-ObjectValues/%s.faces.time.7", hostname);
	   	FILE *file_ftime7;
	   	file_ftime7 = fopen(path_ftime7, "r");
	   	char object_ftime7[100];

	 	if (file_ftime7 == NULL) {
	   	file_ftime7 = fopen(path_ftime7, "w+");
	   	fprintf(file_ftime7,"time7=NULL\n");
	   	rewind(file_ftime7);
	   	}

	   	char path_ftime8[100];
	   	sprintf(path_ftime8, "/home/user/ccndStatus-ObjectValues/%s.faces.time.8", hostname);
	   	FILE *file_ftime8;
	   	file_ftime8 = fopen(path_ftime8, "r");
	   	char object_ftime8[100];

	 	if (file_ftime8 == NULL) {
	   	file_ftime8 = fopen(path_ftime8, "w+");
	   	fprintf(file_ftime8,"time8=NULL\n");
	   	rewind(file_ftime8);
	   	}

	   	char path_ftime9[100];
	   	sprintf(path_ftime9, "/home/user/ccndStatus-ObjectValues/%s.faces.time.9", hostname);
	   	FILE *file_ftime9;
	   	file_ftime9 = fopen(path_ftime9, "r");
	   	char object_ftime9[100];

	 	if (file_ftime9 == NULL) {
	   	file_ftime9 = fopen(path_ftime9, "w+");
	   	fprintf(file_ftime9,"time9=NULL\n");
	   	rewind(file_ftime9);
	   	}

	   	char path_ftime10[100];
	   	sprintf(path_ftime10, "/home/user/ccndStatus-ObjectValues/%s.faces.time.10", hostname);
	   	FILE *file_ftime10;
	   	file_ftime10 = fopen(path_ftime10, "r");
	   	char object_ftime10[100];

	 	if (file_ftime10 == NULL) {
	   	file_ftime10 = fopen(path_ftime10, "w+");
	   	fprintf(file_ftime10,"time10=NULL\n");
	   	rewind(file_ftime10);
	   	}

	   	char path_ftime11[100];
	   	sprintf(path_ftime11, "/home/user/ccndStatus-ObjectValues/%s.faces.time.11", hostname);
	   	FILE *file_ftime11;
	   	file_ftime11 = fopen(path_ftime11, "r");
	   	char object_ftime11[100];

	 	if (file_ftime11 == NULL) {
	   	file_ftime11 = fopen(path_ftime11, "w+");
	   	fprintf(file_ftime11,"time11=NULL\n");
	   	rewind(file_ftime11);
	   	}

	   	char path_ftime12[100];
	   	sprintf(path_ftime12, "/home/user/ccndStatus-ObjectValues/%s.faces.time.12", hostname);
	   	FILE *file_ftime12;
	   	file_ftime12 = fopen(path_ftime12, "r");
	   	char object_ftime12[100];

	 	if (file_ftime12 == NULL) {
	   	file_ftime12 = fopen(path_ftime12, "w+");
	   	fprintf(file_ftime12,"time12=NULL\n");
	   	rewind(file_ftime12);
	   	}

	   	char path_ftime13[100];
	   	sprintf(path_ftime13, "/home/user/ccndStatus-ObjectValues/%s.faces.time.13", hostname);
	   	FILE *file_ftime13;
	   	file_ftime13 = fopen(path_ftime13, "r");
	   	char object_ftime13[100];

	 	if (file_ftime13 == NULL) {
	   	file_ftime13 = fopen(path_ftime13, "w+");
	   	fprintf(file_ftime13,"time13=NULL\n");
	   	rewind(file_ftime13);
	   	}

	//valores de cada objeto de ccndStatus/faces
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE0] = strdup (fgets (object_fface0, sizeof(object_fface0), file_fface0)); fclose(file_fface0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE1] = strdup (fgets (object_fface1, sizeof(object_fface1), file_fface1)); fclose(file_fface1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE2] = strdup (fgets (object_fface2, sizeof(object_fface2), file_fface2)); fclose(file_fface2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE3] = strdup (fgets (object_fface3, sizeof(object_fface3), file_fface3)); fclose(file_fface3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE4] = strdup (fgets (object_fface4, sizeof(object_fface4), file_fface4)); fclose(file_fface4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE5] = strdup (fgets (object_fface5, sizeof(object_fface5), file_fface5)); fclose(file_fface5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE6] = strdup (fgets (object_fface6, sizeof(object_fface6), file_fface6)); fclose(file_fface6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE7] = strdup (fgets (object_fface7, sizeof(object_fface7), file_fface7)); fclose(file_fface7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE8] = strdup (fgets (object_fface8, sizeof(object_fface8), file_fface8)); fclose(file_fface8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE9] = strdup (fgets (object_fface9, sizeof(object_fface9), file_fface9)); fclose(file_fface9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE10] = strdup (fgets (object_fface10, sizeof(object_fface10), file_fface10)); fclose(file_fface10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE11] = strdup (fgets (object_fface11, sizeof(object_fface11), file_fface11)); fclose(file_fface11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE12] = strdup (fgets (object_fface12, sizeof(object_fface12), file_fface12)); fclose(file_fface12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFACE13] = strdup (fgets (object_fface13, sizeof(object_fface13), file_fface13)); fclose(file_fface13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS0] = strdup (fgets (object_fflags0, sizeof(object_fflags0), file_fflags0)); fclose(file_fflags0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS1] = strdup (fgets (object_fflags1, sizeof(object_fflags1), file_fflags1)); fclose(file_fflags1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS2] = strdup (fgets (object_fflags2, sizeof(object_fflags2), file_fflags2)); fclose(file_fflags2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS3] = strdup (fgets (object_fflags3, sizeof(object_fflags3), file_fflags3)); fclose(file_fflags3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS4] = strdup (fgets (object_fflags4, sizeof(object_fflags4), file_fflags4)); fclose(file_fflags4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS5] = strdup (fgets (object_fflags5, sizeof(object_fflags5), file_fflags5)); fclose(file_fflags5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS6] = strdup (fgets (object_fflags6, sizeof(object_fflags6), file_fflags6)); fclose(file_fflags6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS7] = strdup (fgets (object_fflags7, sizeof(object_fflags7), file_fflags7)); fclose(file_fflags7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS8] = strdup (fgets (object_fflags8, sizeof(object_fflags8), file_fflags8)); fclose(file_fflags8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS9] = strdup (fgets (object_fflags9, sizeof(object_fflags9), file_fflags9)); fclose(file_fflags9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS10] = strdup (fgets (object_fflags10, sizeof(object_fflags10), file_fflags10)); fclose(file_fflags10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS11] = strdup (fgets (object_fflags11, sizeof(object_fflags11), file_fflags11)); fclose(file_fflags11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS12] = strdup (fgets (object_fflags12, sizeof(object_fflags12), file_fflags12)); fclose(file_fflags12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FFLAGS13] = strdup (fgets (object_fflags13, sizeof(object_fflags13), file_fflags13)); fclose(file_fflags13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL0] = strdup (fgets (object_flocal0, sizeof(object_flocal0), file_flocal0)); fclose(file_flocal0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL1] = strdup (fgets (object_flocal1, sizeof(object_flocal1), file_flocal1)); fclose(file_flocal1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL2] = strdup (fgets (object_flocal2, sizeof(object_flocal2), file_flocal2)); fclose(file_flocal2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL3] = strdup (fgets (object_flocal3, sizeof(object_flocal3), file_flocal3)); fclose(file_flocal3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL4] = strdup (fgets (object_flocal4, sizeof(object_flocal4), file_flocal4)); fclose(file_flocal4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL5] = strdup (fgets (object_flocal5, sizeof(object_flocal5), file_flocal5)); fclose(file_flocal5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL6] = strdup (fgets (object_flocal6, sizeof(object_flocal6), file_flocal6)); fclose(file_flocal6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL7] = strdup (fgets (object_flocal7, sizeof(object_flocal7), file_flocal7)); fclose(file_flocal7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL8] = strdup (fgets (object_flocal8, sizeof(object_flocal8), file_flocal8)); fclose(file_flocal8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL9] = strdup (fgets (object_flocal9, sizeof(object_flocal9), file_flocal9)); fclose(file_flocal9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL10] = strdup (fgets (object_flocal10, sizeof(object_flocal10), file_flocal10)); fclose(file_flocal10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL11] = strdup (fgets (object_flocal11, sizeof(object_flocal11), file_flocal11)); fclose(file_flocal11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL12] = strdup (fgets (object_flocal12, sizeof(object_flocal12), file_flocal12)); fclose(file_flocal12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FLOCAL13] = strdup (fgets (object_flocal13, sizeof(object_flocal13), file_flocal13)); fclose(file_flocal13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING0] = strdup (fgets (object_fpending0, sizeof(object_fpending0), file_fpending0)); fclose(file_fpending0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING1] = strdup (fgets (object_fpending1, sizeof(object_fpending1), file_fpending1)); fclose(file_fpending1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING2] = strdup (fgets (object_fpending2, sizeof(object_fpending2), file_fpending2)); fclose(file_fpending2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING3] = strdup (fgets (object_fpending3, sizeof(object_fpending3), file_fpending3)); fclose(file_fpending3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING4] = strdup (fgets (object_fpending4, sizeof(object_fpending4), file_fpending4)); fclose(file_fpending4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING5] = strdup (fgets (object_fpending5, sizeof(object_fpending5), file_fpending5)); fclose(file_fpending5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING6] = strdup (fgets (object_fpending6, sizeof(object_fpending6), file_fpending6)); fclose(file_fpending6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING7] = strdup (fgets (object_fpending7, sizeof(object_fpending7), file_fpending7)); fclose(file_fpending7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING8] = strdup (fgets (object_fpending8, sizeof(object_fpending8), file_fpending8)); fclose(file_fpending8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING9] = strdup (fgets (object_fpending9, sizeof(object_fpending9), file_fpending9)); fclose(file_fpending9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING10] = strdup (fgets (object_fpending10, sizeof(object_fpending10), file_fpending10)); fclose(file_fpending10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING11] = strdup (fgets (object_fpending11, sizeof(object_fpending11), file_fpending11)); fclose(file_fpending11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING12] = strdup (fgets (object_fpending12, sizeof(object_fpending12), file_fpending12)); fclose(file_fpending12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FPENDING13] = strdup (fgets (object_fpending13, sizeof(object_fpending13), file_fpending13)); fclose(file_fpending13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE0] = strdup (fgets (object_fremote0, sizeof(object_fremote0), file_fremote0)); fclose(file_fremote0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE1] = strdup (fgets (object_fremote1, sizeof(object_fremote1), file_fremote1)); fclose(file_fremote1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE2] = strdup (fgets (object_fremote2, sizeof(object_fremote2), file_fremote2)); fclose(file_fremote2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE3] = strdup (fgets (object_fremote3, sizeof(object_fremote3), file_fremote3)); fclose(file_fremote3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE4] = strdup (fgets (object_fremote4, sizeof(object_fremote4), file_fremote4)); fclose(file_fremote4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE5] = strdup (fgets (object_fremote5, sizeof(object_fremote5), file_fremote5)); fclose(file_fremote5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE6] = strdup (fgets (object_fremote6, sizeof(object_fremote6), file_fremote6)); fclose(file_fremote6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE7] = strdup (fgets (object_fremote7, sizeof(object_fremote7), file_fremote7)); fclose(file_fremote7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE8] = strdup (fgets (object_fremote8, sizeof(object_fremote8), file_fremote8)); fclose(file_fremote8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE9] = strdup (fgets (object_fremote9, sizeof(object_fremote9), file_fremote9)); fclose(file_fremote9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE10] = strdup (fgets (object_fremote10, sizeof(object_fremote10), file_fremote10)); fclose(file_fremote10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE11] = strdup (fgets (object_fremote11, sizeof(object_fremote11), file_fremote11)); fclose(file_fremote11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE12] = strdup (fgets (object_fremote12, sizeof(object_fremote12), file_fremote12)); fclose(file_fremote12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FREMOTE13] = strdup (fgets (object_fremote13, sizeof(object_fremote13), file_fremote13)); fclose(file_fremote13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST0] = strdup (fgets (object_fhostname0, sizeof(object_fhostname0), file_fhostname0)); fclose(file_fhostname0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST1] = strdup (fgets (object_fhostname1, sizeof(object_fhostname1), file_fhostname1)); fclose(file_fhostname1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST2] = strdup (fgets (object_fhostname2, sizeof(object_fhostname2), file_fhostname2)); fclose(file_fhostname2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST3] = strdup (fgets (object_fhostname3, sizeof(object_fhostname3), file_fhostname3)); fclose(file_fhostname3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST4] = strdup (fgets (object_fhostname4, sizeof(object_fhostname4), file_fhostname4)); fclose(file_fhostname4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST5] = strdup (fgets (object_fhostname5, sizeof(object_fhostname5), file_fhostname5)); fclose(file_fhostname5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST6] = strdup (fgets (object_fhostname6, sizeof(object_fhostname6), file_fhostname6)); fclose(file_fhostname6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST7] = strdup (fgets (object_fhostname7, sizeof(object_fhostname7), file_fhostname7)); fclose(file_fhostname7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST8] = strdup (fgets (object_fhostname8, sizeof(object_fhostname8), file_fhostname8)); fclose(file_fhostname8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST9] = strdup (fgets (object_fhostname9, sizeof(object_fhostname9), file_fhostname9)); fclose(file_fhostname9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST10] = strdup (fgets (object_fhostname10, sizeof(object_fhostname10), file_fhostname10)); fclose(file_fhostname10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST11] = strdup (fgets (object_fhostname11, sizeof(object_fhostname11), file_fhostname11)); fclose(file_fhostname11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST12] = strdup (fgets (object_fhostname12, sizeof(object_fhostname12), file_fhostname12)); fclose(file_fhostname12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FHOST13] = strdup (fgets (object_fhostname13, sizeof(object_fhostname13), file_fhostname13)); fclose(file_fhostname13);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP0] = strdup (fgets (object_ftime0, sizeof(object_ftime0), file_ftime0)); fclose(file_ftime0);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP1] = strdup (fgets (object_ftime1, sizeof(object_ftime1), file_ftime1)); fclose(file_ftime1);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP2] = strdup (fgets (object_ftime2, sizeof(object_ftime2), file_ftime2)); fclose(file_ftime2);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP3] = strdup (fgets (object_ftime3, sizeof(object_ftime3), file_ftime3)); fclose(file_ftime3);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP4] = strdup (fgets (object_ftime4, sizeof(object_ftime4), file_ftime4)); fclose(file_ftime4);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP5] = strdup (fgets (object_ftime5, sizeof(object_ftime5), file_ftime5)); fclose(file_ftime5);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP6] = strdup (fgets (object_ftime6, sizeof(object_ftime6), file_ftime6)); fclose(file_ftime6);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP7] = strdup (fgets (object_ftime7, sizeof(object_ftime7), file_ftime7)); fclose(file_ftime7);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP8] = strdup (fgets (object_ftime8, sizeof(object_ftime8), file_ftime8)); fclose(file_ftime8);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP9] = strdup (fgets (object_ftime9, sizeof(object_ftime9), file_ftime9)); fclose(file_ftime9);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP10] = strdup (fgets (object_ftime10, sizeof(object_ftime10), file_ftime10)); fclose(file_ftime10);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP11] = strdup (fgets (object_ftime11, sizeof(object_ftime11), file_ftime11)); fclose(file_ftime11);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP12] = strdup (fgets (object_ftime12, sizeof(object_ftime12), file_ftime12)); fclose(file_ftime12);
	   	ccnMibStatusFacesObjectValue[CCN_STATUS_FACES_OBJECT_FTIMESTAMP13] = strdup (fgets (object_ftime13, sizeof(object_ftime13), file_ftime13)); fclose(file_ftime13);


	//leitura de arquivos com conteudo de cada objeto de ccndStatus/faceActivityRates

	   	char path_farface0[100];
	   	sprintf(path_farface0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.0", hostname);
	   	FILE *file_farface0;
	   	file_farface0 = fopen(path_farface0, "r");
	   	char object_farface0[100];

	 	if (file_farface0 == NULL) {
	   	file_farface0 = fopen(path_farface0, "w+");
	   	fprintf(file_farface0,"face0=NULL\n");
	   	rewind(file_farface0);
	   	}

	   	char path_farface1[100];
	   	sprintf(path_farface1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.1", hostname);
	   	FILE *file_farface1;
	   	file_farface1 = fopen(path_farface1, "r");
	   	char object_farface1[100];

	 	if (file_farface1 == NULL) {
	   	file_farface1 = fopen(path_farface1, "w+");
	   	fprintf(file_farface1,"face1=NULL\n");
	   	rewind(file_farface1);
	   	}

		char path_farface2[100];
	   	sprintf(path_farface2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.2", hostname);
	   	FILE *file_farface2;
	   	file_farface2 = fopen(path_farface2, "r");
	   	char object_farface2[100];

	 	if (file_farface2 == NULL) {
	   	file_farface2 = fopen(path_farface2, "w+");
	   	fprintf(file_farface2,"face2=NULL\n");
	   	rewind(file_farface2);
	   	}

		char path_farface3[100];
	   	sprintf(path_farface3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.3", hostname);
	   	FILE *file_farface3;
	   	file_farface3 = fopen(path_farface3, "r");
	   	char object_farface3[100];

	 	if (file_farface3 == NULL) {
	   	file_farface3 = fopen(path_farface3, "w+");
	   	fprintf(file_farface3,"face3=NULL\n");
	   	rewind(file_farface3);
	   	}

		char path_farface4[100];
	   	sprintf(path_farface4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.4", hostname);
	   	FILE *file_farface4;
	   	file_farface4 = fopen(path_farface4, "r");
	   	char object_farface4[100];

	 	if (file_farface4 == NULL) {
	   	file_farface4 = fopen(path_farface4, "w+");
	   	fprintf(file_farface4,"face4=NULL\n");
	   	rewind(file_farface4);
	   	}

		char path_farface5[100];
	   	sprintf(path_farface5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.5", hostname);
	   	FILE *file_farface5;
	   	file_farface5 = fopen(path_farface5, "r");
	   	char object_farface5[100];

	 	if (file_farface5 == NULL) {
	   	file_farface5 = fopen(path_farface5, "w+");
	   	fprintf(file_farface5,"face5=NULL\n");
	   	rewind(file_farface5);
	   	}

		char path_farface6[100];
	   	sprintf(path_farface6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.6", hostname);
	   	FILE *file_farface6;
	   	file_farface6 = fopen(path_farface6, "r");
	   	char object_farface6[100];

	 	if (file_farface6 == NULL) {
	   	file_farface6 = fopen(path_farface6, "w+");
	   	fprintf(file_farface6,"face6=NULL\n");
	   	rewind(file_farface6);
	   	}

		char path_farface7[100];
	   	sprintf(path_farface7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.7", hostname);
	   	FILE *file_farface7;
	   	file_farface7 = fopen(path_farface7, "r");
	   	char object_farface7[100];

	 	if (file_farface7 == NULL) {
	   	file_farface7 = fopen(path_farface7, "w+");
	   	fprintf(file_farface7,"face7=NULL\n");
	   	rewind(file_farface7);
	   	}

		char path_farface8[100];
	   	sprintf(path_farface8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.face.8", hostname);
	   	FILE *file_farface8;
	   	file_farface8 = fopen(path_farface8, "r");
	   	char object_farface8[100];

	 	if (file_farface8 == NULL) {
	   	file_farface8 = fopen(path_farface8, "w+");
	   	fprintf(file_farface8,"face8=NULL\n");
	   	rewind(file_farface8);
	   	}

	   	char path_farBIn0[100];
	   	sprintf(path_farBIn0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.0", hostname);
	   	FILE *file_farBIn0;
	   	file_farBIn0 = fopen(path_farBIn0, "r");
	   	char object_farBIn0[100];

	 	if (file_farBIn0 == NULL) {
	   	file_farBIn0 = fopen(path_farBIn0, "w+");
	   	fprintf(file_farBIn0,"BIn0=NULL\n");
	   	rewind(file_farBIn0);
	   	}

	 	char path_farBIn1[100];
	   	sprintf(path_farBIn1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.1", hostname);
	   	FILE *file_farBIn1;
	   	file_farBIn1 = fopen(path_farBIn1, "r");
	   	char object_farBIn1[100];

	 	if (file_farBIn1 == NULL) {
	   	file_farBIn1 = fopen(path_farBIn1, "w+");
	   	fprintf(file_farBIn1,"BIn1=NULL\n");
	   	rewind(file_farBIn1);
	   	}

	 	char path_farBIn2[100];
	   	sprintf(path_farBIn2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.2", hostname);
	   	FILE *file_farBIn2;
	   	file_farBIn2 = fopen(path_farBIn2, "r");
	   	char object_farBIn2[100];

	 	if (file_farBIn2 == NULL) {
	   	file_farBIn2 = fopen(path_farBIn2, "w+");
	   	fprintf(file_farBIn2,"BIn2=NULL\n");
	   	rewind(file_farBIn2);
	   	}

	 	char path_farBIn3[100];
	   	sprintf(path_farBIn3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.3", hostname);
	   	FILE *file_farBIn3;
	   	file_farBIn3 = fopen(path_farBIn3, "r");
	   	char object_farBIn3[100];

	 	if (file_farBIn3 == NULL) {
	   	file_farBIn3 = fopen(path_farBIn3, "w+");
	   	fprintf(file_farBIn3,"BIn3=NULL\n");
	   	rewind(file_farBIn3);
	   	}

	 	char path_farBIn4[100];
	   	sprintf(path_farBIn4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.4", hostname);
	   	FILE *file_farBIn4;
	   	file_farBIn4 = fopen(path_farBIn4, "r");
	   	char object_farBIn4[100];

	 	if (file_farBIn4 == NULL) {
	   	file_farBIn4 = fopen(path_farBIn4, "w+");
	   	fprintf(file_farBIn4,"BIn4=NULL\n");
	   	rewind(file_farBIn4);
	   	}

	 	char path_farBIn5[100];
	   	sprintf(path_farBIn5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.5", hostname);
	   	FILE *file_farBIn5;
	   	file_farBIn5 = fopen(path_farBIn5, "r");
	   	char object_farBIn5[100];

	 	if (file_farBIn5 == NULL) {
	   	file_farBIn5 = fopen(path_farBIn5, "w+");
	   	fprintf(file_farBIn5,"BIn5=NULL\n");
	   	rewind(file_farBIn5);
	   	}

	 	char path_farBIn6[100];
	   	sprintf(path_farBIn6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.6", hostname);
	   	FILE *file_farBIn6;
	   	file_farBIn6 = fopen(path_farBIn6, "r");
	   	char object_farBIn6[100];

	 	if (file_farBIn6 == NULL) {
	   	file_farBIn6 = fopen(path_farBIn6, "w+");
	   	fprintf(file_farBIn6,"BIn6=NULL\n");
	   	rewind(file_farBIn6);
	   	}

	 	char path_farBIn7[100];
	   	sprintf(path_farBIn7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.7", hostname);
	   	FILE *file_farBIn7;
	   	file_farBIn7 = fopen(path_farBIn7, "r");
	   	char object_farBIn7[100];

	 	if (file_farBIn7 == NULL) {
	   	file_farBIn7 = fopen(path_farBIn7, "w+");
	   	fprintf(file_farBIn7,"BIn7=NULL\n");
	   	rewind(file_farBIn7);
	   	}

	 	char path_farBIn8[100];
	   	sprintf(path_farBIn8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BIn.8", hostname);
	   	FILE *file_farBIn8;
	   	file_farBIn8 = fopen(path_farBIn8, "r");
	   	char object_farBIn8[100];

	 	if (file_farBIn8 == NULL) {
	   	file_farBIn8 = fopen(path_farBIn8, "w+");
	   	fprintf(file_farBIn8,"BIn8=NULL\n");
	   	rewind(file_farBIn8);
	   	}

	   	char path_farBOut0[100];
	   	sprintf(path_farBOut0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.0", hostname);
	   	FILE *file_farBOut0;
	   	file_farBOut0 = fopen(path_farBOut0, "r");
		char object_farBOut0[100];

	 	if (file_farBOut0 == NULL) {
	   	file_farBOut0 = fopen(path_farBOut0, "w+");
	   	fprintf(file_farBOut0,"BOut0=NULL\n");
	   	rewind(file_farBOut0);
	   	}

	   	char path_farBOut1[100];
	   	sprintf(path_farBOut1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.1", hostname);
	   	FILE *file_farBOut1;
	   	file_farBOut1 = fopen(path_farBOut1, "r");
		char object_farBOut1[100];

	 	if (file_farBOut1 == NULL) {
	   	file_farBOut1 = fopen(path_farBOut1, "w+");
	   	fprintf(file_farBOut1,"BOut1=NULL\n");
	   	rewind(file_farBOut1);
	   	}

	   	char path_farBOut2[100];
	   	sprintf(path_farBOut2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.2", hostname);
	   	FILE *file_farBOut2;
	   	file_farBOut2 = fopen(path_farBOut2, "r");
		char object_farBOut2[100];

	 	if (file_farBOut2 == NULL) {
	   	file_farBOut2 = fopen(path_farBOut2, "w+");
	   	fprintf(file_farBOut2,"BOut2=NULL\n");
	   	rewind(file_farBOut2);
	   	}

	   	char path_farBOut3[100];
	   	sprintf(path_farBOut3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.3", hostname);
	   	FILE *file_farBOut3;
	   	file_farBOut3 = fopen(path_farBOut3, "r");
		char object_farBOut3[100];

	 	if (file_farBOut3 == NULL) {
	   	file_farBOut3 = fopen(path_farBOut3, "w+");
	   	fprintf(file_farBOut3,"BOut3=NULL\n");
	   	rewind(file_farBOut3);
	   	}

	   	char path_farBOut4[100];
	   	sprintf(path_farBOut4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.4", hostname);
	   	FILE *file_farBOut4;
	   	file_farBOut4 = fopen(path_farBOut4, "r");
		char object_farBOut4[100];

	 	if (file_farBOut4 == NULL) {
	   	file_farBOut4 = fopen(path_farBOut4, "w+");
	   	fprintf(file_farBOut4,"BOut4=NULL\n");
	   	rewind(file_farBOut4);
	   	}

	   	char path_farBOut5[100];
	   	sprintf(path_farBOut5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.5", hostname);
	   	FILE *file_farBOut5;
	   	file_farBOut5 = fopen(path_farBOut5, "r");
		char object_farBOut5[100];

	 	if (file_farBOut5 == NULL) {
	   	file_farBOut5 = fopen(path_farBOut5, "w+");
	   	fprintf(file_farBOut5,"BOut5=NULL\n");
	   	rewind(file_farBOut5);
	   	}

	   	char path_farBOut6[100];
	   	sprintf(path_farBOut6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.6", hostname);
	   	FILE *file_farBOut6;
	   	file_farBOut6 = fopen(path_farBOut6, "r");
		char object_farBOut6[100];

	 	if (file_farBOut6 == NULL) {
	   	file_farBOut6 = fopen(path_farBOut6, "w+");
	   	fprintf(file_farBOut6,"BOut6=NULL\n");
	   	rewind(file_farBOut6);
	   	}

	   	char path_farBOut7[100];
	   	sprintf(path_farBOut7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.7", hostname);
	   	FILE *file_farBOut7;
	   	file_farBOut7 = fopen(path_farBOut7, "r");
		char object_farBOut7[100];

	 	if (file_farBOut7 == NULL) {
	   	file_farBOut7 = fopen(path_farBOut7, "w+");
	   	fprintf(file_farBOut7,"BOut7=NULL\n");
	   	rewind(file_farBOut7);
	   	}

	   	char path_farBOut8[100];
	   	sprintf(path_farBOut8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.BOut.8", hostname);
	   	FILE *file_farBOut8;
	   	file_farBOut8 = fopen(path_farBOut8, "r");
		char object_farBOut8[100];

	 	if (file_farBOut8 == NULL) {
	   	file_farBOut8 = fopen(path_farBOut8, "w+");
	   	fprintf(file_farBOut8,"BOut8=NULL\n");
	   	rewind(file_farBOut8);
	   	}

	  	char path_farrData0[100];
	  	sprintf(path_farrData0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.0", hostname);
	   	FILE *file_farrData0;
	   	file_farrData0 = fopen(path_farrData0, "r");
	   	char object_farrData0[100];

	 	if (file_farrData0 == NULL) {
	   	file_farrData0 = fopen(path_farrData0, "w+");
	   	fprintf(file_farrData0,"rData0=NULL\n");
	   	rewind(file_farrData0);
	   	}

	  	char path_farrData1[100];
	  	sprintf(path_farrData1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.1", hostname);
	   	FILE *file_farrData1;
	   	file_farrData1 = fopen(path_farrData1, "r");
	   	char object_farrData1[100];

	 	if (file_farrData1 == NULL) {
	   	file_farrData1 = fopen(path_farrData1, "w+");
	   	fprintf(file_farrData1,"rData1=NULL\n");
	   	rewind(file_farrData1);
	   	}

	  	char path_farrData2[100];
	  	sprintf(path_farrData2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.2", hostname);
	   	FILE *file_farrData2;
	   	file_farrData2 = fopen(path_farrData2, "r");
	   	char object_farrData2[100];

	 	if (file_farrData2 == NULL) {
	   	file_farrData2 = fopen(path_farrData2, "w+");
	   	fprintf(file_farrData2,"rData2=NULL\n");
	   	rewind(file_farrData2);
	   	}

	  	char path_farrData3[100];
	  	sprintf(path_farrData3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.3", hostname);
	   	FILE *file_farrData3;
	   	file_farrData3 = fopen(path_farrData3, "r");
	   	char object_farrData3[100];

	 	if (file_farrData3 == NULL) {
	   	file_farrData3 = fopen(path_farrData3, "w+");
	   	fprintf(file_farrData3,"rData3=NULL\n");
	   	rewind(file_farrData3);
	   	}

	  	char path_farrData4[100];
	  	sprintf(path_farrData4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.4", hostname);
	   	FILE *file_farrData4;
	   	file_farrData4 = fopen(path_farrData4, "r");
	   	char object_farrData4[100];

	 	if (file_farrData4 == NULL) {
	   	file_farrData4 = fopen(path_farrData4, "w+");
	   	fprintf(file_farrData4,"rData4=NULL\n");
	   	rewind(file_farrData4);
	   	}

	  	char path_farrData5[100];
	  	sprintf(path_farrData5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.5", hostname);
	   	FILE *file_farrData5;
	   	file_farrData5 = fopen(path_farrData5, "r");
	   	char object_farrData5[100];

	 	if (file_farrData5 == NULL) {
	   	file_farrData5 = fopen(path_farrData5, "w+");
	   	fprintf(file_farrData5,"rData5=NULL\n");
	   	rewind(file_farrData5);
	   	}

	  	char path_farrData6[100];
	  	sprintf(path_farrData6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.6", hostname);
	   	FILE *file_farrData6;
	   	file_farrData6 = fopen(path_farrData6, "r");
	   	char object_farrData6[100];

	 	if (file_farrData6 == NULL) {
	   	file_farrData6 = fopen(path_farrData6, "w+");
	   	fprintf(file_farrData6,"rData6=NULL\n");
	   	rewind(file_farrData6);
	   	}

	  	char path_farrData7[100];
	  	sprintf(path_farrData7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.7", hostname);
	   	FILE *file_farrData7;
	   	file_farrData7 = fopen(path_farrData7, "r");
	   	char object_farrData7[100];

	 	if (file_farrData7 == NULL) {
	   	file_farrData7 = fopen(path_farrData7, "w+");
	   	fprintf(file_farrData7,"rData7=NULL\n");
	   	rewind(file_farrData7);
	   	}

	  	char path_farrData8[100];
	  	sprintf(path_farrData8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rData.8", hostname);
	   	FILE *file_farrData8;
	   	file_farrData8 = fopen(path_farrData8, "r");
	   	char object_farrData8[100];

	 	if (file_farrData8 == NULL) {
	   	file_farrData8 = fopen(path_farrData8, "w+");
	   	fprintf(file_farrData8,"rData8=NULL\n");
	   	rewind(file_farrData8);
	   	}

	   	char path_farsData0[100];
	   	sprintf(path_farsData0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.0", hostname);
	   	FILE *file_farsData0;
	   	file_farsData0 = fopen(path_farsData0, "r");
	   	char object_farsData0[100];

	 	if (file_farsData0 == NULL) {
	   	file_farsData0 = fopen(path_farsData0, "w+");
	   	fprintf(file_farsData0,"sData0=NULL\n");
	   	rewind(file_farsData0);
	   	}

	   	char path_farsData1[100];
	   	sprintf(path_farsData1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.1", hostname);
	   	FILE *file_farsData1;
	   	file_farsData1 = fopen(path_farsData1, "r");
	   	char object_farsData1[100];

	 	if (file_farsData1 == NULL) {
	   	file_farsData1 = fopen(path_farsData1, "w+");
	   	fprintf(file_farsData1,"sData1=NULL\n");
	   	rewind(file_farsData1);
	   	}

	   	char path_farsData2[100];
	   	sprintf(path_farsData2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.2", hostname);
	   	FILE *file_farsData2;
	   	file_farsData2 = fopen(path_farsData2, "r");
	   	char object_farsData2[100];

	 	if (file_farsData2 == NULL) {
	   	file_farsData2 = fopen(path_farsData2, "w+");
	   	fprintf(file_farsData2,"sData2=NULL\n");
	   	rewind(file_farsData2);
	   	}

	   	char path_farsData3[100];
	   	sprintf(path_farsData3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.3", hostname);
	   	FILE *file_farsData3;
	   	file_farsData3 = fopen(path_farsData3, "r");
	   	char object_farsData3[100];

	 	if (file_farsData3 == NULL) {
	   	file_farsData3 = fopen(path_farsData3, "w+");
	   	fprintf(file_farsData3,"sData3=NULL\n");
	   	rewind(file_farsData3);
	   	}

	   	char path_farsData4[100];
	   	sprintf(path_farsData4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.4", hostname);
	   	FILE *file_farsData4;
	   	file_farsData4 = fopen(path_farsData4, "r");
	   	char object_farsData4[100];

	 	if (file_farsData4 == NULL) {
	   	file_farsData4 = fopen(path_farsData4, "w+");
	   	fprintf(file_farsData4,"sData4=NULL\n");
	   	rewind(file_farsData4);
	   	}

	   	char path_farsData5[100];
	   	sprintf(path_farsData5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.5", hostname);
	   	FILE *file_farsData5;
	   	file_farsData5 = fopen(path_farsData5, "r");
	   	char object_farsData5[100];

	 	if (file_farsData5 == NULL) {
	   	file_farsData5 = fopen(path_farsData5, "w+");
	   	fprintf(file_farsData5,"sData5=NULL\n");
	   	rewind(file_farsData5);
	   	}

	   	char path_farsData6[100];
	   	sprintf(path_farsData6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.6", hostname);
	   	FILE *file_farsData6;
	   	file_farsData6 = fopen(path_farsData6, "r");
	   	char object_farsData6[100];

	 	if (file_farsData6 == NULL) {
	   	file_farsData6 = fopen(path_farsData6, "w+");
	   	fprintf(file_farsData6,"sData6=NULL\n");
	   	rewind(file_farsData6);
	   	}

	   	char path_farsData7[100];
	   	sprintf(path_farsData7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.7", hostname);
	   	FILE *file_farsData7;
	   	file_farsData7 = fopen(path_farsData7, "r");
	   	char object_farsData7[100];

	 	if (file_farsData7 == NULL) {
	   	file_farsData7 = fopen(path_farsData7, "w+");
	   	fprintf(file_farsData7,"sData7=NULL\n");
	   	rewind(file_farsData7);
	   	}

	   	char path_farsData8[100];
	   	sprintf(path_farsData8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sData.8", hostname);
	   	FILE *file_farsData8;
	   	file_farsData8 = fopen(path_farsData8, "r");
	   	char object_farsData8[100];

	 	if (file_farsData8 == NULL) {
	   	file_farsData8 = fopen(path_farsData8, "w+");
	   	fprintf(file_farsData8,"sData8=NULL\n");
	   	rewind(file_farsData8);
	   	}

		char path_farrInt0[100];
	   	sprintf(path_farrInt0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.0", hostname);
	   	FILE *file_farrInt0;
	   	file_farrInt0 = fopen(path_farrInt0, "r");
	   	char object_farrInt0[100];

	 	if (file_farrInt0 == NULL) {
	   	file_farrInt0 = fopen(path_farrInt0, "w+");
	   	fprintf(file_farrInt0,"rInt0=NULL\n");
	   	rewind(file_farrInt0);
	   	}

		char path_farrInt1[100];
	   	sprintf(path_farrInt1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.1", hostname);
	   	FILE *file_farrInt1;
	   	file_farrInt1 = fopen(path_farrInt1, "r");
	   	char object_farrInt1[100];

	 	if (file_farrInt1 == NULL) {
	   	file_farrInt1 = fopen(path_farrInt1, "w+");
	   	fprintf(file_farrInt1,"rInt1=NULL\n");
	   	rewind(file_farrInt1);
	   	}

		char path_farrInt2[100];
	   	sprintf(path_farrInt2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.2", hostname);
	   	FILE *file_farrInt2;
	   	file_farrInt2 = fopen(path_farrInt2, "r");
	   	char object_farrInt2[100];

	 	if (file_farrInt2 == NULL) {
	   	file_farrInt2 = fopen(path_farrInt2, "w+");
	   	fprintf(file_farrInt2,"rInt2=NULL\n");
	   	rewind(file_farrInt2);
	   	}

		char path_farrInt3[100];
	   	sprintf(path_farrInt3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.3", hostname);
	   	FILE *file_farrInt3;
	   	file_farrInt3 = fopen(path_farrInt3, "r");
	   	char object_farrInt3[100];

	 	if (file_farrInt3 == NULL) {
	   	file_farrInt3 = fopen(path_farrInt3, "w+");
	   	fprintf(file_farrInt3,"rInt3=NULL\n");
	   	rewind(file_farrInt3);
	   	}

		char path_farrInt4[100];
	   	sprintf(path_farrInt4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.4", hostname);
	   	FILE *file_farrInt4;
	   	file_farrInt4 = fopen(path_farrInt4, "r");
	   	char object_farrInt4[100];

	 	if (file_farrInt4 == NULL) {
	   	file_farrInt4 = fopen(path_farrInt4, "w+");
	   	fprintf(file_farrInt4,"rInt4=NULL\n");
	   	rewind(file_farrInt4);
	   	}

		char path_farrInt5[100];
	   	sprintf(path_farrInt5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.5", hostname);
	   	FILE *file_farrInt5;
	   	file_farrInt5 = fopen(path_farrInt5, "r");
	   	char object_farrInt5[100];

	 	if (file_farrInt5 == NULL) {
	   	file_farrInt5 = fopen(path_farrInt5, "w+");
	   	fprintf(file_farrInt5,"rInt5=NULL\n");
	   	rewind(file_farrInt5);
	   	}

		char path_farrInt6[100];
	   	sprintf(path_farrInt6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.6", hostname);
	   	FILE *file_farrInt6;
	   	file_farrInt6 = fopen(path_farrInt6, "r");
	   	char object_farrInt6[100];

	 	if (file_farrInt6 == NULL) {
	   	file_farrInt6 = fopen(path_farrInt6, "w+");
	   	fprintf(file_farrInt6,"rInt6=NULL\n");
	   	rewind(file_farrInt6);
	   	}

		char path_farrInt7[100];
	   	sprintf(path_farrInt7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.7", hostname);
	   	FILE *file_farrInt7;
	   	file_farrInt7 = fopen(path_farrInt7, "r");
	   	char object_farrInt7[100];

	 	if (file_farrInt7 == NULL) {
	   	file_farrInt7 = fopen(path_farrInt7, "w+");
	   	fprintf(file_farrInt7,"rInt7=NULL\n");
	   	rewind(file_farrInt7);
	   	}

		char path_farrInt8[100];
	   	sprintf(path_farrInt8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.rInt.8", hostname);
	   	FILE *file_farrInt8;
	   	file_farrInt8 = fopen(path_farrInt8, "r");
	   	char object_farrInt8[100];

	 	if (file_farrInt8 == NULL) {
	   	file_farrInt8 = fopen(path_farrInt8, "w+");
	   	fprintf(file_farrInt8,"rInt8=NULL\n");
	   	rewind(file_farrInt8);
	   	}

		char path_farsInt0[100];
	   	sprintf(path_farsInt0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.0", hostname);
	   	FILE *file_farsInt0;
	   	file_farsInt0 = fopen(path_farsInt0, "r");
	   	char object_farsInt0[100];

	 	if (file_farsInt0 == NULL) {
	   	file_farsInt0 = fopen(path_farsInt0, "w+");
	   	fprintf(file_farsInt0,"sInt0=NULL\n");
	   	rewind(file_farsInt0);
	   	}

		char path_farsInt1[100];
	   	sprintf(path_farsInt1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.1", hostname);
	   	FILE *file_farsInt1;
	   	file_farsInt1 = fopen(path_farsInt1, "r");
	   	char object_farsInt1[100];

	 	if (file_farsInt1 == NULL) {
	   	file_farsInt1 = fopen(path_farsInt1, "w+");
	   	fprintf(file_farsInt1,"sInt1=NULL\n");
	   	rewind(file_farsInt1);
	   	}

		char path_farsInt2[100];
	   	sprintf(path_farsInt2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.2", hostname);
	   	FILE *file_farsInt2;
	   	file_farsInt2 = fopen(path_farsInt2, "r");
	   	char object_farsInt2[100];

	 	if (file_farsInt2 == NULL) {
	   	file_farsInt2 = fopen(path_farsInt2, "w+");
	   	fprintf(file_farsInt2,"sInt2=NULL\n");
	   	rewind(file_farsInt2);
	   	}

		char path_farsInt3[100];
	   	sprintf(path_farsInt3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.3", hostname);
	   	FILE *file_farsInt3;
	   	file_farsInt3 = fopen(path_farsInt3, "r");
	   	char object_farsInt3[100];

	 	if (file_farsInt3 == NULL) {
	   	file_farsInt3 = fopen(path_farsInt3, "w+");
	   	fprintf(file_farsInt3,"sInt3=NULL\n");
	   	rewind(file_farsInt3);
	   	}

		char path_farsInt4[100];
	   	sprintf(path_farsInt4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.4", hostname);
	   	FILE *file_farsInt4;
	   	file_farsInt4 = fopen(path_farsInt4, "r");
	   	char object_farsInt4[100];

	 	if (file_farsInt4 == NULL) {
	   	file_farsInt4 = fopen(path_farsInt4, "w+");
	   	fprintf(file_farsInt4,"sInt4=NULL\n");
	   	rewind(file_farsInt4);
	   	}

		char path_farsInt5[100];
	   	sprintf(path_farsInt5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.5", hostname);
	   	FILE *file_farsInt5;
	   	file_farsInt5 = fopen(path_farsInt5, "r");
	   	char object_farsInt5[100];

	 	if (file_farsInt5 == NULL) {
	   	file_farsInt5 = fopen(path_farsInt5, "w+");
	   	fprintf(file_farsInt5,"sInt5=NULL\n");
	   	rewind(file_farsInt5);
	   	}

		char path_farsInt6[100];
	   	sprintf(path_farsInt6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.6", hostname);
	   	FILE *file_farsInt6;
	   	file_farsInt6 = fopen(path_farsInt6, "r");
	   	char object_farsInt6[100];

	 	if (file_farsInt6 == NULL) {
	   	file_farsInt6 = fopen(path_farsInt6, "w+");
	   	fprintf(file_farsInt6,"sInt6=NULL\n");
	   	rewind(file_farsInt6);
	   	}

		char path_farsInt7[100];
	   	sprintf(path_farsInt7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.7", hostname);
	   	FILE *file_farsInt7;
	   	file_farsInt7 = fopen(path_farsInt7, "r");
	   	char object_farsInt7[100];

	 	if (file_farsInt7 == NULL) {
	   	file_farsInt7 = fopen(path_farsInt7, "w+");
	   	fprintf(file_farsInt7,"sInt7=NULL\n");
	   	rewind(file_farsInt7);
	   	}

		char path_farsInt8[100];
	   	sprintf(path_farsInt8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.sInt.8", hostname);
	   	FILE *file_farsInt8;
	   	file_farsInt8 = fopen(path_farsInt8, "r");
	   	char object_farsInt8[100];

	 	if (file_farsInt8 == NULL) {
	   	file_farsInt8 = fopen(path_farsInt8, "w+");
	   	fprintf(file_farsInt8,"sInt8=NULL\n");
	   	rewind(file_farsInt8);
	   	}

	   	char path_farhostname0[100];
	   	sprintf(path_farhostname0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.0", hostname);
	  	FILE *file_farhostname0;
		file_farhostname0 = fopen(path_farhostname0, "r");
	   	char object_farhostname0[100];

	 	if (file_farhostname0 == NULL) {
	   	file_farhostname0 = fopen(path_farhostname0, "w+");
	   	fprintf(file_farhostname0,"hostname0=NULL\n");
	   	rewind(file_farhostname0);
	   	}

	   	char path_farhostname1[100];
	   	sprintf(path_farhostname1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.1", hostname);
	  	FILE *file_farhostname1;
		file_farhostname1 = fopen(path_farhostname1, "r");
	   	char object_farhostname1[100];

	 	if (file_farhostname1 == NULL) {
	   	file_farhostname1 = fopen(path_farhostname1, "w+");
	   	fprintf(file_farhostname1,"hostname1=NULL\n");
	   	rewind(file_farhostname1);
	   	}

	   	char path_farhostname2[100];
	   	sprintf(path_farhostname2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.2", hostname);
	  	FILE *file_farhostname2;
		file_farhostname2 = fopen(path_farhostname2, "r");
	   	char object_farhostname2[100];

	 	if (file_farhostname2 == NULL) {
	   	file_farhostname2 = fopen(path_farhostname2, "w+");
	   	fprintf(file_farhostname2,"hostname2=NULL\n");
	   	rewind(file_farhostname2);
	   	}

	   	char path_farhostname3[100];
	   	sprintf(path_farhostname3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.3", hostname);
	  	FILE *file_farhostname3;
		file_farhostname3 = fopen(path_farhostname3, "r");
	   	char object_farhostname3[100];

	 	if (file_farhostname3 == NULL) {
	   	file_farhostname3 = fopen(path_farhostname3, "w+");
	   	fprintf(file_farhostname3,"hostname3=NULL\n");
	   	rewind(file_farhostname3);
	   	}

	   	char path_farhostname4[100];
	   	sprintf(path_farhostname4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.4", hostname);
	  	FILE *file_farhostname4;
		file_farhostname4 = fopen(path_farhostname4, "r");
	   	char object_farhostname4[100];

	 	if (file_farhostname4 == NULL) {
	   	file_farhostname4 = fopen(path_farhostname4, "w+");
	   	fprintf(file_farhostname4,"hostname4=NULL\n");
	   	rewind(file_farhostname4);
	   	}

	   	char path_farhostname5[100];
	   	sprintf(path_farhostname5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.5", hostname);
	  	FILE *file_farhostname5;
		file_farhostname5 = fopen(path_farhostname5, "r");
	   	char object_farhostname5[100];

	 	if (file_farhostname5 == NULL) {
	   	file_farhostname5 = fopen(path_farhostname5, "w+");
	   	fprintf(file_farhostname5,"hostname5=NULL\n");
	   	rewind(file_farhostname5);
	   	}

	   	char path_farhostname6[100];
	   	sprintf(path_farhostname6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.6", hostname);
	  	FILE *file_farhostname6;
		file_farhostname6 = fopen(path_farhostname6, "r");
	   	char object_farhostname6[100];

	 	if (file_farhostname6 == NULL) {
	   	file_farhostname6 = fopen(path_farhostname6, "w+");
	   	fprintf(file_farhostname6,"hostname6=NULL\n");
	   	rewind(file_farhostname6);
	   	}

	   	char path_farhostname7[100];
	   	sprintf(path_farhostname7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.7", hostname);
	  	FILE *file_farhostname7;
		file_farhostname7 = fopen(path_farhostname7, "r");
	   	char object_farhostname7[100];

	 	if (file_farhostname7 == NULL) {
	   	file_farhostname7 = fopen(path_farhostname7, "w+");
	   	fprintf(file_farhostname7,"hostname7=NULL\n");
	   	rewind(file_farhostname7);
	   	}

	   	char path_farhostname8[100];
	   	sprintf(path_farhostname8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.hostname.8", hostname);
	  	FILE *file_farhostname8;
		file_farhostname8 = fopen(path_farhostname8, "r");
	   	char object_farhostname8[100];

	 	if (file_farhostname8 == NULL) {
	   	file_farhostname8 = fopen(path_farhostname8, "w+");
	   	fprintf(file_farhostname8,"hostname8=NULL\n");
	   	rewind(file_farhostname8);
	   	}

	  	char path_fartime0[100];
	  	sprintf(path_fartime0, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.0", hostname);
	   	FILE *file_fartime0;
	   	file_fartime0 = fopen(path_fartime0, "r");
	   	char object_fartime0[100];

	 	if (file_fartime0 == NULL) {
	   	file_fartime0 = fopen(path_fartime0, "w+");
	   	fprintf(file_fartime0,"time0=NULL\n");
	   	rewind(file_fartime0);
	   	}

	  	char path_fartime1[100];
	  	sprintf(path_fartime1, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.1", hostname);
	   	FILE *file_fartime1;
	   	file_fartime1 = fopen(path_fartime1, "r");
	   	char object_fartime1[100];

	 	if (file_fartime1 == NULL) {
	   	file_fartime1 = fopen(path_fartime1, "w+");
	   	fprintf(file_fartime1,"time1=NULL\n");
	   	rewind(file_fartime1);
	   	}

	  	char path_fartime2[100];
	  	sprintf(path_fartime2, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.2", hostname);
	   	FILE *file_fartime2;
	   	file_fartime2 = fopen(path_fartime2, "r");
	   	char object_fartime2[100];

	 	if (file_fartime2 == NULL) {
	   	file_fartime2 = fopen(path_fartime2, "w+");
	   	fprintf(file_fartime2,"time2=NULL\n");
	   	rewind(file_fartime2);
	   	}

	  	char path_fartime3[100];
	  	sprintf(path_fartime3, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.3", hostname);
	   	FILE *file_fartime3;
	   	file_fartime3 = fopen(path_fartime3, "r");
	   	char object_fartime3[100];

	 	if (file_fartime3 == NULL) {
	   	file_fartime3 = fopen(path_fartime3, "w+");
	   	fprintf(file_fartime3,"time3=NULL\n");
	   	rewind(file_fartime3);
	   	}

	  	char path_fartime4[100];
	  	sprintf(path_fartime4, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.4", hostname);
	   	FILE *file_fartime4;
	   	file_fartime4 = fopen(path_fartime4, "r");
	   	char object_fartime4[100];

	 	if (file_fartime4 == NULL) {
	   	file_fartime4 = fopen(path_fartime4, "w+");
	   	fprintf(file_fartime4,"time4=NULL\n");
	   	rewind(file_fartime4);
	   	}

	  	char path_fartime5[100];
	  	sprintf(path_fartime5, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.5", hostname);
	   	FILE *file_fartime5;
	   	file_fartime5 = fopen(path_fartime5, "r");
	   	char object_fartime5[100];

	 	if (file_fartime5 == NULL) {
	   	file_fartime5 = fopen(path_fartime5, "w+");
	   	fprintf(file_fartime5,"time5=NULL\n");
	   	rewind(file_fartime5);
	   	}

	  	char path_fartime6[100];
	  	sprintf(path_fartime6, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.6", hostname);
	   	FILE *file_fartime6;
	   	file_fartime6 = fopen(path_fartime6, "r");
	   	char object_fartime6[100];

	 	if (file_fartime6 == NULL) {
	   	file_fartime6 = fopen(path_fartime6, "w+");
	   	fprintf(file_fartime6,"time6=NULL\n");
	   	rewind(file_fartime6);
	   	}

	  	char path_fartime7[100];
	  	sprintf(path_fartime7, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.7", hostname);
	   	FILE *file_fartime7;
	   	file_fartime7 = fopen(path_fartime7, "r");
	   	char object_fartime7[100];

	 	if (file_fartime7 == NULL) {
	   	file_fartime7 = fopen(path_fartime7, "w+");
	   	fprintf(file_fartime7,"time7=NULL\n");
	   	rewind(file_fartime7);
	   	}

	  	char path_fartime8[100];
	  	sprintf(path_fartime8, "/home/user/ccndStatus-ObjectValues/%s.face_activity_rates.time.8", hostname);
	   	FILE *file_fartime8;
	   	file_fartime8 = fopen(path_fartime8, "r");
	   	char object_fartime8[100];

	 	if (file_fartime8 == NULL) {
	   	file_fartime8 = fopen(path_fartime8, "w+");
	   	fprintf(file_fartime8,"time8=NULL\n");
	   	rewind(file_fartime8);
	   	}

	//valores de cada objeto de ccndStatus/faceActivityRates
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE0] = strdup (fgets (object_farface0, sizeof(object_farface0), file_farface0)); fclose(file_farface0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE1] = strdup (fgets (object_farface1, sizeof(object_farface1), file_farface1)); fclose(file_farface1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE2] = strdup (fgets (object_farface2, sizeof(object_farface2), file_farface2)); fclose(file_farface2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE3] = strdup (fgets (object_farface3, sizeof(object_farface3), file_farface3)); fclose(file_farface3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE4] = strdup (fgets (object_farface4, sizeof(object_farface4), file_farface4)); fclose(file_farface4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE5] = strdup (fgets (object_farface5, sizeof(object_farface5), file_farface5)); fclose(file_farface5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE6] = strdup (fgets (object_farface6, sizeof(object_farface6), file_farface6)); fclose(file_farface6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE7] = strdup (fgets (object_farface7, sizeof(object_farface7), file_farface7)); fclose(file_farface7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARFACE8] = strdup (fgets (object_farface8, sizeof(object_farface8), file_farface8)); fclose(file_farface8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN0] = strdup (fgets (object_farBIn0, sizeof(object_farBIn0), file_farBIn0)); fclose(file_farBIn0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN1] = strdup (fgets (object_farBIn1, sizeof(object_farBIn1), file_farBIn1)); fclose(file_farBIn1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN2] = strdup (fgets (object_farBIn2, sizeof(object_farBIn2), file_farBIn2)); fclose(file_farBIn2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN3] = strdup (fgets (object_farBIn3, sizeof(object_farBIn3), file_farBIn3)); fclose(file_farBIn3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN4] = strdup (fgets (object_farBIn4, sizeof(object_farBIn4), file_farBIn4)); fclose(file_farBIn4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN5] = strdup (fgets (object_farBIn5, sizeof(object_farBIn5), file_farBIn5)); fclose(file_farBIn5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN6] = strdup (fgets (object_farBIn6, sizeof(object_farBIn6), file_farBIn6)); fclose(file_farBIn6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN7] = strdup (fgets (object_farBIn7, sizeof(object_farBIn7), file_farBIn7)); fclose(file_farBIn7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESIN8] = strdup (fgets (object_farBIn8, sizeof(object_farBIn8), file_farBIn8)); fclose(file_farBIn8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT0] = strdup (fgets (object_farBOut0, sizeof(object_farBOut0), file_farBOut0)); fclose(file_farBOut0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT1] = strdup (fgets (object_farBOut1, sizeof(object_farBOut1), file_farBOut1)); fclose(file_farBOut1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT2] = strdup (fgets (object_farBOut2, sizeof(object_farBOut2), file_farBOut2)); fclose(file_farBOut2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT3] = strdup (fgets (object_farBOut3, sizeof(object_farBOut3), file_farBOut3)); fclose(file_farBOut3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT4] = strdup (fgets (object_farBOut4, sizeof(object_farBOut4), file_farBOut4)); fclose(file_farBOut4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT5] = strdup (fgets (object_farBOut5, sizeof(object_farBOut5), file_farBOut5)); fclose(file_farBOut5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT6] = strdup (fgets (object_farBOut6, sizeof(object_farBOut6), file_farBOut6)); fclose(file_farBOut6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT7] = strdup (fgets (object_farBOut7, sizeof(object_farBOut7), file_farBOut7)); fclose(file_farBOut7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARBYTESOUT8] = strdup (fgets (object_farBOut8, sizeof(object_farBOut8), file_farBOut8)); fclose(file_farBOut8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA0] = strdup (fgets (object_farrData0, sizeof(object_farrData0), file_farrData0)); fclose(file_farrData0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA1] = strdup (fgets (object_farrData1, sizeof(object_farrData1), file_farrData1)); fclose(file_farrData1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA2] = strdup (fgets (object_farrData2, sizeof(object_farrData2), file_farrData2)); fclose(file_farrData2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA3] = strdup (fgets (object_farrData3, sizeof(object_farrData3), file_farrData3)); fclose(file_farrData3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA4] = strdup (fgets (object_farrData4, sizeof(object_farrData4), file_farrData4)); fclose(file_farrData4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA5] = strdup (fgets (object_farrData5, sizeof(object_farrData5), file_farrData5)); fclose(file_farrData5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA6] = strdup (fgets (object_farrData6, sizeof(object_farrData6), file_farrData6)); fclose(file_farrData6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA7] = strdup (fgets (object_farrData7, sizeof(object_farrData7), file_farrData7)); fclose(file_farrData7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARRECEIVEDDATA8] = strdup (fgets (object_farrData8, sizeof(object_farrData8), file_farrData8)); fclose(file_farrData8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA0] = strdup (fgets (object_farsData0, sizeof(object_farsData0), file_farsData0)); fclose(file_farsData0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA1] = strdup (fgets (object_farsData1, sizeof(object_farsData1), file_farsData1)); fclose(file_farsData1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA2] = strdup (fgets (object_farsData2, sizeof(object_farsData2), file_farsData2)); fclose(file_farsData2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA3] = strdup (fgets (object_farsData3, sizeof(object_farsData3), file_farsData3)); fclose(file_farsData3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA4] = strdup (fgets (object_farsData4, sizeof(object_farsData4), file_farsData4)); fclose(file_farsData4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA5] = strdup (fgets (object_farsData5, sizeof(object_farsData5), file_farsData5)); fclose(file_farsData5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA6] = strdup (fgets (object_farsData6, sizeof(object_farsData6), file_farsData6)); fclose(file_farsData6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA7] = strdup (fgets (object_farsData7, sizeof(object_farsData7), file_farsData7)); fclose(file_farsData7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARSENTDATA8] = strdup (fgets (object_farsData8, sizeof(object_farsData8), file_farsData8)); fclose(file_farsData8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED0] = strdup (fgets (object_farrInt0, sizeof(object_farrInt0), file_farrInt0)); fclose(file_farrInt0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED1] = strdup (fgets (object_farrInt1, sizeof(object_farrInt1), file_farrInt1)); fclose(file_farrInt1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED2] = strdup (fgets (object_farrInt2, sizeof(object_farrInt2), file_farrInt2)); fclose(file_farrInt2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED3] = strdup (fgets (object_farrInt3, sizeof(object_farrInt3), file_farrInt3)); fclose(file_farrInt3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED4] = strdup (fgets (object_farrInt4, sizeof(object_farrInt4), file_farrInt4)); fclose(file_farrInt4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED5] = strdup (fgets (object_farrInt5, sizeof(object_farrInt5), file_farrInt5)); fclose(file_farrInt5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED6] = strdup (fgets (object_farrInt6, sizeof(object_farrInt6), file_farrInt6)); fclose(file_farrInt6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED7] = strdup (fgets (object_farrInt7, sizeof(object_farrInt7), file_farrInt7)); fclose(file_farrInt7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESTSRECEIVED8] = strdup (fgets (object_farrInt8, sizeof(object_farrInt8), file_farrInt8)); fclose(file_farrInt8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT0] = strdup (fgets (object_farsInt0, sizeof(object_farsInt0), file_farsInt0)); fclose(file_farsInt0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT1] = strdup (fgets (object_farsInt1, sizeof(object_farsInt1), file_farsInt1)); fclose(file_farsInt1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT2] = strdup (fgets (object_farsInt2, sizeof(object_farsInt2), file_farsInt2)); fclose(file_farsInt2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT3] = strdup (fgets (object_farsInt3, sizeof(object_farsInt3), file_farsInt3)); fclose(file_farsInt3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT4] = strdup (fgets (object_farsInt4, sizeof(object_farsInt4), file_farsInt4)); fclose(file_farsInt4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT5] = strdup (fgets (object_farsInt5, sizeof(object_farsInt5), file_farsInt5)); fclose(file_farsInt5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT6] = strdup (fgets (object_farsInt6, sizeof(object_farsInt6), file_farsInt6)); fclose(file_farsInt6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT7] = strdup (fgets (object_farsInt7, sizeof(object_farsInt7), file_farsInt7)); fclose(file_farsInt7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARINTERESSENT8] = strdup (fgets (object_farsInt8, sizeof(object_farsInt8), file_farsInt8)); fclose(file_farsInt8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST0] = strdup (fgets (object_farhostname0, sizeof(object_farhostname0), file_farhostname0)); fclose(file_farhostname0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST1] = strdup (fgets (object_farhostname1, sizeof(object_farhostname1), file_farhostname1)); fclose(file_farhostname1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST2] = strdup (fgets (object_farhostname2, sizeof(object_farhostname2), file_farhostname2)); fclose(file_farhostname2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST3] = strdup (fgets (object_farhostname3, sizeof(object_farhostname3), file_farhostname3)); fclose(file_farhostname3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST4] = strdup (fgets (object_farhostname4, sizeof(object_farhostname4), file_farhostname4)); fclose(file_farhostname4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST5] = strdup (fgets (object_farhostname5, sizeof(object_farhostname5), file_farhostname5)); fclose(file_farhostname5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST6] = strdup (fgets (object_farhostname6, sizeof(object_farhostname6), file_farhostname6)); fclose(file_farhostname6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST7] = strdup (fgets (object_farhostname7, sizeof(object_farhostname7), file_farhostname7)); fclose(file_farhostname7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARHOST8] = strdup (fgets (object_farhostname8, sizeof(object_farhostname8), file_farhostname8)); fclose(file_farhostname8);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP0] = strdup (fgets (object_fartime0, sizeof(object_fartime0), file_fartime0)); fclose(file_fartime0);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP1] = strdup (fgets (object_fartime1, sizeof(object_fartime1), file_fartime1)); fclose(file_fartime1);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP2] = strdup (fgets (object_fartime2, sizeof(object_fartime2), file_fartime2)); fclose(file_fartime2);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP3] = strdup (fgets (object_fartime3, sizeof(object_fartime3), file_fartime3)); fclose(file_fartime3);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP4] = strdup (fgets (object_fartime4, sizeof(object_fartime4), file_fartime4)); fclose(file_fartime4);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP5] = strdup (fgets (object_fartime5, sizeof(object_fartime5), file_fartime5)); fclose(file_fartime5);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP6] = strdup (fgets (object_fartime6, sizeof(object_fartime6), file_fartime6)); fclose(file_fartime6);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP7] = strdup (fgets (object_fartime7, sizeof(object_fartime7), file_fartime7)); fclose(file_fartime7);
	   	ccnMibStatusfaceActivityRatesObjectValue[CCN_STATUS_FACE_ACTIVITY_RATES_OBJECT_FARTIMESTAMP8] = strdup (fgets (object_fartime8, sizeof(object_fartime8), file_fartime8)); fclose(file_fartime8);

	//leitura de arquivos com conteudo de cada objeto de ccndStatus/forwarding

	   	char path_fwface0[100];
	   	sprintf(path_fwface0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.0", hostname);
	   	FILE *file_fwface0;
	   	file_fwface0 = fopen(path_fwface0, "r");
	   	char object_fwface0[100];

	 	if (file_fwface0 == NULL) {
	   	file_fwface0 = fopen(path_fwface0, "w+");
	   	fprintf(file_fwface0,"face0=NULL\n");
	   	rewind(file_fwface0);
	   	}

	   	char path_fwface1[100];
	   	sprintf(path_fwface1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.1", hostname);
	   	FILE *file_fwface1;
	   	file_fwface1 = fopen(path_fwface1, "r");
	   	char object_fwface1[100];

	 	if (file_fwface1 == NULL) {
	   	file_fwface1 = fopen(path_fwface1, "w+");
	   	fprintf(file_fwface1,"face1=NULL\n");
	   	rewind(file_fwface1);
	   	}

	   	char path_fwface2[100];
	   	sprintf(path_fwface2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.2", hostname);
	   	FILE *file_fwface2;
	   	file_fwface2 = fopen(path_fwface2, "r");
	   	char object_fwface2[100];

	 	if (file_fwface2== NULL) {
	   	file_fwface2 = fopen(path_fwface2, "w+");
	   	fprintf(file_fwface2,"face2=NULL\n");
	   	rewind(file_fwface2);
	   	}

	   	char path_fwface3[100];
	   	sprintf(path_fwface3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.3", hostname);
	   	FILE *file_fwface3;
	   	file_fwface3 = fopen(path_fwface3, "r");
	   	char object_fwface3[100];

	 	if (file_fwface3 == NULL) {
	   	file_fwface3 = fopen(path_fwface3, "w+");
	   	fprintf(file_fwface3,"face3=NULL\n");
	   	rewind(file_fwface3);
	   	}

	   	char path_fwface4[100];
	   	sprintf(path_fwface4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.4", hostname);
	   	FILE *file_fwface4;
	   	file_fwface4 = fopen(path_fwface4, "r");
	   	char object_fwface4[100];

	 	if (file_fwface4 == NULL) {
	   	file_fwface4 = fopen(path_fwface4, "w+");
	   	fprintf(file_fwface4,"face4=NULL\n");
	   	rewind(file_fwface4);
	   	}

	   	char path_fwface5[100];
	   	sprintf(path_fwface5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.5", hostname);
	   	FILE *file_fwface5;
	   	file_fwface5 = fopen(path_fwface5, "r");
	   	char object_fwface5[100];

	 	if (file_fwface5 == NULL) {
	   	file_fwface5 = fopen(path_fwface5, "w+");
	   	fprintf(file_fwface5,"face5=NULL\n");
	   	rewind(file_fwface5);
	   	}

	   	char path_fwface6[100];
	   	sprintf(path_fwface6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.6", hostname);
	   	FILE *file_fwface6;
	   	file_fwface6 = fopen(path_fwface6, "r");
	   	char object_fwface6[100];

	 	if (file_fwface6 == NULL) {
	   	file_fwface6 = fopen(path_fwface6, "w+");
	   	fprintf(file_fwface6,"face6=NULL\n");
	   	rewind(file_fwface6);
	   	}

	   	char path_fwface7[100];
	   	sprintf(path_fwface7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.7", hostname);
	   	FILE *file_fwface7;
	   	file_fwface7 = fopen(path_fwface7, "r");
	   	char object_fwface7[100];

	 	if (file_fwface7 == NULL) {
	   	file_fwface7 = fopen(path_fwface7, "w+");
	   	fprintf(file_fwface7,"face7=NULL\n");
	   	rewind(file_fwface7);
	   	}

	   	char path_fwface8[100];
	   	sprintf(path_fwface8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.8", hostname);
	   	FILE *file_fwface8;
	   	file_fwface8 = fopen(path_fwface8, "r");
	   	char object_fwface8[100];

	 	if (file_fwface8 == NULL) {
	   	file_fwface8 = fopen(path_fwface8, "w+");
	   	fprintf(file_fwface8,"face8=NULL\n");
	   	rewind(file_fwface8);
	   	}

	   	char path_fwface9[100];
	   	sprintf(path_fwface9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.9", hostname);
	   	FILE *file_fwface9;
	   	file_fwface9 = fopen(path_fwface9, "r");
	   	char object_fwface9[100];

	 	if (file_fwface9 == NULL) {
	   	file_fwface9 = fopen(path_fwface9, "w+");
	   	fprintf(file_fwface9,"face9=NULL\n");
	   	rewind(file_fwface9);
	   	}

	   	char path_fwface10[100];
	   	sprintf(path_fwface10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.face.10", hostname);
	   	FILE *file_fwface10;
	   	file_fwface10 = fopen(path_fwface10, "r");
	   	char object_fwface10[100];

	 	if (file_fwface10 == NULL) {
	   	file_fwface10 = fopen(path_fwface10, "w+");
	   	fprintf(file_fwface10,"face10=NULL\n");
	   	rewind(file_fwface10);
	   	}

	   	char path_fwflags0[100];
	   	sprintf(path_fwflags0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.0", hostname);
	   	FILE *file_fwflags0;
	   	file_fwflags0 = fopen(path_fwflags0, "r");
	   	char object_fwflags0[100];

	 	if (file_fwflags0 == NULL) {
	   	file_fwflags0 = fopen(path_fwflags0, "w+");
	   	fprintf(file_fwflags0,"flags0=NULL\n");
	   	rewind(file_fwflags0);
	   	}

	   	char path_fwflags1[100];
	   	sprintf(path_fwflags1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.1", hostname);
	   	FILE *file_fwflags1;
	   	file_fwflags1 = fopen(path_fwflags1, "r");
	   	char object_fwflags1[100];

	 	if (file_fwflags1 == NULL) {
	   	file_fwflags1 = fopen(path_fwflags1, "w+");
	   	fprintf(file_fwflags1,"flags1=NULL\n");
	   	rewind(file_fwflags1);
	   	}

	   	char path_fwflags2[100];
	   	sprintf(path_fwflags2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.2", hostname);
	   	FILE *file_fwflags2;
	   	file_fwflags2 = fopen(path_fwflags2, "r");
	   	char object_fwflags2[100];

	 	if (file_fwflags2 == NULL) {
	   	file_fwflags2 = fopen(path_fwflags2, "w+");
	   	fprintf(file_fwflags2,"flags2=NULL\n");
	   	rewind(file_fwflags2);
	   	}

	   	char path_fwflags3[100];
	   	sprintf(path_fwflags3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.3", hostname);
	   	FILE *file_fwflags3;
	   	file_fwflags3 = fopen(path_fwflags3, "r");
	   	char object_fwflags3[100];

	 	if (file_fwflags3 == NULL) {
	   	file_fwflags3 = fopen(path_fwflags3, "w+");
	   	fprintf(file_fwflags3,"flags3=NULL\n");
	   	rewind(file_fwflags3);
	   	}

	   	char path_fwflags4[100];
	   	sprintf(path_fwflags4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.4", hostname);
	   	FILE *file_fwflags4;
	   	file_fwflags4 = fopen(path_fwflags4, "r");
	   	char object_fwflags4[100];

	 	if (file_fwflags4 == NULL) {
	   	file_fwflags4 = fopen(path_fwflags4, "w+");
	   	fprintf(file_fwflags4,"flags4=NULL\n");
	   	rewind(file_fwflags4);
	   	}

	   	char path_fwflags5[100];
	   	sprintf(path_fwflags5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.5", hostname);
	   	FILE *file_fwflags5;
	   	file_fwflags5 = fopen(path_fwflags5, "r");
	   	char object_fwflags5[100];

	 	if (file_fwflags5 == NULL) {
	   	file_fwflags5 = fopen(path_fwflags5, "w+");
	   	fprintf(file_fwflags5,"flags5=NULL\n");
	   	rewind(file_fwflags5);
	   	}

	   	char path_fwflags6[100];
	   	sprintf(path_fwflags6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.6", hostname);
	   	FILE *file_fwflags6;
	   	file_fwflags6 = fopen(path_fwflags6, "r");
	   	char object_fwflags6[100];

	 	if (file_fwflags6== NULL) {
	   	file_fwflags6 = fopen(path_fwflags6, "w+");
	   	fprintf(file_fwflags6,"flags6=NULL\n");
	   	rewind(file_fwflags6);
	   	}

	   	char path_fwflags7[100];
	   	sprintf(path_fwflags7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.7", hostname);
	   	FILE *file_fwflags7;
	   	file_fwflags7 = fopen(path_fwflags7, "r");
	   	char object_fwflags7[100];

	 	if (file_fwflags7 == NULL) {
	   	file_fwflags7 = fopen(path_fwflags7, "w+");
	   	fprintf(file_fwflags7,"flags7=NULL\n");
	   	rewind(file_fwflags7);
	   	}

	   	char path_fwflags8[100];
	   	sprintf(path_fwflags8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.8", hostname);
	   	FILE *file_fwflags8;
	   	file_fwflags8 = fopen(path_fwflags8, "r");
	   	char object_fwflags8[100];

	 	if (file_fwflags8 == NULL) {
	   	file_fwflags8 = fopen(path_fwflags8, "w+");
	   	fprintf(file_fwflags8,"flags8=NULL\n");
	   	rewind(file_fwflags8);
	   	}

	   	char path_fwflags9[100];
	   	sprintf(path_fwflags9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.9", hostname);
	   	FILE *file_fwflags9;
	   	file_fwflags9 = fopen(path_fwflags9, "r");
	   	char object_fwflags9[100];

	 	if (file_fwflags9 == NULL) {
	   	file_fwflags9 = fopen(path_fwflags9, "w+");
	   	fprintf(file_fwflags9,"flags9=NULL\n");
	   	rewind(file_fwflags9);
	   	}

	   	char path_fwflags10[100];
	   	sprintf(path_fwflags10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.flags.10", hostname);
	   	FILE *file_fwflags10;
	   	file_fwflags10 = fopen(path_fwflags10, "r");
	   	char object_fwflags10[100];

	 	if (file_fwflags10 == NULL) {
	   	file_fwflags10 = fopen(path_fwflags10, "w+");
	   	fprintf(file_fwflags10,"flags10=NULL\n");
	   	rewind(file_fwflags10);
	   	}

	   	char path_fwpath0[100];
	   	sprintf(path_fwpath0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.0", hostname);
	   	FILE *file_fwpath0;
	   	file_fwpath0 = fopen(path_fwpath0, "r");
		char object_fwpath0[100];

	 	if (file_fwpath0 == NULL) {
	   	file_fwpath0 = fopen(path_fwpath0, "w+");
	   	fprintf(file_fwpath0,"path0=NULL\n");
	   	rewind(file_fwpath0);
	   	}

	   	char path_fwpath1[100];
	   	sprintf(path_fwpath1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.1", hostname);
	   	FILE *file_fwpath1;
	   	file_fwpath1 = fopen(path_fwpath1, "r");
		char object_fwpath1[100];

	 	if (file_fwpath1 == NULL) {
	   	file_fwpath1 = fopen(path_fwpath1, "w+");
	   	fprintf(file_fwpath1,"path1=NULL\n");
	   	rewind(file_fwpath1);
	   	}

	   	char path_fwpath2[100];
	   	sprintf(path_fwpath2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.2", hostname);
	   	FILE *file_fwpath2;
	   	file_fwpath2 = fopen(path_fwpath2, "r");
		char object_fwpath2[100];

	 	if (file_fwpath2 == NULL) {
	   	file_fwpath2 = fopen(path_fwpath2, "w+");
	   	fprintf(file_fwpath2,"path2=NULL\n");
	   	rewind(file_fwpath2);
	   	}

	   	char path_fwpath3[100];
	   	sprintf(path_fwpath3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.3", hostname);
	   	FILE *file_fwpath3;
	   	file_fwpath3 = fopen(path_fwpath3, "r");
		char object_fwpath3[100];

	 	if (file_fwpath3 == NULL) {
	   	file_fwpath3 = fopen(path_fwpath3, "w+");
	   	fprintf(file_fwpath3,"path3=NULL\n");
	   	rewind(file_fwpath3);
	   	}

	   	char path_fwpath4[100];
	   	sprintf(path_fwpath4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.4", hostname);
	   	FILE *file_fwpath4;
	   	file_fwpath4 = fopen(path_fwpath4, "r");
		char object_fwpath4[100];

	 	if (file_fwpath4 == NULL) {
	   	file_fwpath4 = fopen(path_fwpath0, "w+");
	   	fprintf(file_fwpath4,"path4=NULL\n");
	   	rewind(file_fwpath4);
	   	}

	   	char path_fwpath5[100];
	   	sprintf(path_fwpath5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.5", hostname);
	   	FILE *file_fwpath5;
	   	file_fwpath5 = fopen(path_fwpath5, "r");
		char object_fwpath5[100];

	 	if (file_fwpath5== NULL) {
	   	file_fwpath5 = fopen(path_fwpath5, "w+");
	   	fprintf(file_fwpath5,"path5=NULL\n");
	   	rewind(file_fwpath5);
	   	}

	   	char path_fwpath6[100];
	   	sprintf(path_fwpath6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.6", hostname);
	   	FILE *file_fwpath6;
	   	file_fwpath6 = fopen(path_fwpath6, "r");
		char object_fwpath6[100];

	 	if (file_fwpath6 == NULL) {
	   	file_fwpath6 = fopen(path_fwpath6, "w+");
	   	fprintf(file_fwpath6,"path6=NULL\n");
	   	rewind(file_fwpath6);
	   	}

	   	char path_fwpath7[100];
	   	sprintf(path_fwpath7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.7", hostname);
	   	FILE *file_fwpath7;
	   	file_fwpath7 = fopen(path_fwpath7, "r");
		char object_fwpath7[100];

	 	if (file_fwpath7 == NULL) {
	   	file_fwpath7 = fopen(path_fwpath7, "w+");
	   	fprintf(file_fwpath7,"path7=NULL\n");
	   	rewind(file_fwpath7);
	   	}

	   	char path_fwpath8[100];
	   	sprintf(path_fwpath8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.8", hostname);
	   	FILE *file_fwpath8;
	   	file_fwpath8 = fopen(path_fwpath8, "r");
		char object_fwpath8[100];

	 	if (file_fwpath8 == NULL) {
	   	file_fwpath8 = fopen(path_fwpath8, "w+");
	   	fprintf(file_fwpath8,"path8=NULL\n");
	   	rewind(file_fwpath8);
	   	}

	   	char path_fwpath9[100];
	   	sprintf(path_fwpath9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.9", hostname);
	   	FILE *file_fwpath9;
	   	file_fwpath9 = fopen(path_fwpath9, "r");
		char object_fwpath9[100];

	 	if (file_fwpath9 == NULL) {
	   	file_fwpath9 = fopen(path_fwpath9, "w+");
	   	fprintf(file_fwpath9,"fwpath9=NULL\n");
	   	rewind(file_fwpath9);
	   	}

	   	char path_fwpath10[100];
	   	sprintf(path_fwpath10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.path.10", hostname);
	   	FILE *file_fwpath10;
	   	file_fwpath10 = fopen(path_fwpath10, "r");
		char object_fwpath10[100];

	 	if (file_fwpath10 == NULL) {
	   	file_fwpath10 = fopen(path_fwpath10, "w+");
	   	fprintf(file_fwpath10,"path10=NULL\n");
	   	rewind(file_fwpath10);
	   	}

	  	char path_fwexpires0[100];
	  	sprintf(path_fwexpires0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.0", hostname);
	   	FILE *file_fwexpires0;
	   	file_fwexpires0 = fopen(path_fwexpires0, "r");
	   	char object_fwexpires0[100];

	 	if (file_fwexpires0 == NULL) {
	   	file_fwexpires0 = fopen(path_fwexpires0, "w+");
	   	fprintf(file_fwexpires0,"expires0=NULL\n");
	   	rewind(file_fwexpires0);
	   	}

	  	char path_fwexpires1[100];
	  	sprintf(path_fwexpires1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.1", hostname);
	   	FILE *file_fwexpires1;
	   	file_fwexpires1 = fopen(path_fwexpires1, "r");
	   	char object_fwexpires1[100];

	 	if (file_fwexpires1 == NULL) {
	   	file_fwexpires1 = fopen(path_fwexpires1, "w+");
	   	fprintf(file_fwexpires1,"expires1=NULL\n");
	   	rewind(file_fwexpires1);
	   	}

	  	char path_fwexpires2[100];
	  	sprintf(path_fwexpires2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.2", hostname);
	   	FILE *file_fwexpires2;
	   	file_fwexpires2 = fopen(path_fwexpires2, "r");
	   	char object_fwexpires2[100];

	 	if (file_fwexpires2 == NULL) {
	   	file_fwexpires2 = fopen(path_fwexpires2, "w+");
	   	fprintf(file_fwexpires2,"expires2=NULL\n");
	   	rewind(file_fwexpires2);
	   	}

	  	char path_fwexpires3[100];
	  	sprintf(path_fwexpires3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.3", hostname);
	   	FILE *file_fwexpires3;
	   	file_fwexpires3 = fopen(path_fwexpires3, "r");
	   	char object_fwexpires3[100];

	 	if (file_fwexpires3 == NULL) {
	   	file_fwexpires3 = fopen(path_fwexpires3, "w+");
	   	fprintf(file_fwexpires3,"expires3=NULL\n");
	   	rewind(file_fwexpires3);
	   	}

	  	char path_fwexpires4[100];
	  	sprintf(path_fwexpires4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.4", hostname);
	   	FILE *file_fwexpires4;
	   	file_fwexpires4 = fopen(path_fwexpires4, "r");
	   	char object_fwexpires4[100];

	 	if (file_fwexpires4 == NULL) {
	   	file_fwexpires4 = fopen(path_fwexpires4, "w+");
	   	fprintf(file_fwexpires4,"expires4=NULL\n");
	   	rewind(file_fwexpires4);
	   	}

	  	char path_fwexpires5[100];
	  	sprintf(path_fwexpires5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.5", hostname);
	   	FILE *file_fwexpires5;
	   	file_fwexpires5 = fopen(path_fwexpires5, "r");
	   	char object_fwexpires5[100];

	 	if (file_fwexpires5 == NULL) {
	   	file_fwexpires5 = fopen(path_fwexpires5, "w+");
	   	fprintf(file_fwexpires5,"expires5=NULL\n");
	   	rewind(file_fwexpires5);
	   	}

	  	char path_fwexpires6[100];
	  	sprintf(path_fwexpires6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.6", hostname);
	   	FILE *file_fwexpires6;
	   	file_fwexpires6 = fopen(path_fwexpires6, "r");
	   	char object_fwexpires6[100];

	 	if (file_fwexpires6 == NULL) {
	   	file_fwexpires6 = fopen(path_fwexpires6, "w+");
	   	fprintf(file_fwexpires6,"expires6=NULL\n");
	   	rewind(file_fwexpires6);
	   	}

	  	char path_fwexpires7[100];
	  	sprintf(path_fwexpires7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.7", hostname);
	   	FILE *file_fwexpires7;
	   	file_fwexpires7 = fopen(path_fwexpires7, "r");
	   	char object_fwexpires7[100];

	 	if (file_fwexpires7 == NULL) {
	   	file_fwexpires7 = fopen(path_fwexpires7, "w+");
	   	fprintf(file_fwexpires7,"expires7=NULL\n");
	   	rewind(file_fwexpires7);
	   	}

	  	char path_fwexpires8[100];
	  	sprintf(path_fwexpires8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.8", hostname);
	   	FILE *file_fwexpires8;
	   	file_fwexpires8 = fopen(path_fwexpires8, "r");
	   	char object_fwexpires8[100];

	 	if (file_fwexpires8 == NULL) {
	   	file_fwexpires8 = fopen(path_fwexpires8, "w+");
	   	fprintf(file_fwexpires8,"expires8=NULL\n");
	   	rewind(file_fwexpires8);
	   	}

	  	char path_fwexpires9[100];
	  	sprintf(path_fwexpires9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.9", hostname);
	   	FILE *file_fwexpires9;
	   	file_fwexpires9 = fopen(path_fwexpires9, "r");
	   	char object_fwexpires9[100];

	 	if (file_fwexpires9 == NULL) {
	   	file_fwexpires9 = fopen(path_fwexpires9, "w+");
	   	fprintf(file_fwexpires9,"expires9=NULL\n");
	   	rewind(file_fwexpires9);
	   	}

	  	char path_fwexpires10[100];
	  	sprintf(path_fwexpires10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.expires.10", hostname);
	   	FILE *file_fwexpires10;
	   	file_fwexpires10 = fopen(path_fwexpires10, "r");
	   	char object_fwexpires10[100];

	 	if (file_fwexpires10 == NULL) {
	   	file_fwexpires10 = fopen(path_fwexpires10, "w+");
	   	fprintf(file_fwexpires10,"expires10=NULL\n");
	   	rewind(file_fwexpires10);
	   	}

	   	char path_fwhostname0[100];
	   	sprintf(path_fwhostname0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.0", hostname);
	  	FILE *file_fwhostname0;
		file_fwhostname0 = fopen(path_fwhostname0, "r");
	   	char object_fwhostname0[100];

	 	if (file_fwhostname0 == NULL) {
	   	file_fwhostname0 = fopen(path_fwhostname0, "w+");
	   	fprintf(file_fwhostname0,"hostname0=NULL\n");
	   	rewind(file_fwhostname0);
	   	}

	   	char path_fwhostname1[100];
	   	sprintf(path_fwhostname1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.1", hostname);
	  	FILE *file_fwhostname1;
		file_fwhostname1 = fopen(path_fwhostname1, "r");
	   	char object_fwhostname1[100];

	 	if (file_fwhostname1 == NULL) {
	   	file_fwhostname1 = fopen(path_fwhostname1, "w+");
	   	fprintf(file_fwhostname1,"hostname1=NULL\n");
	   	rewind(file_fwhostname1);
	   	}

	   	char path_fwhostname2[100];
	   	sprintf(path_fwhostname2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.2", hostname);
	  	FILE *file_fwhostname2;
		file_fwhostname2 = fopen(path_fwhostname2, "r");
	   	char object_fwhostname2[100];

	 	if (file_fwhostname2 == NULL) {
	   	file_fwhostname2 = fopen(path_fwhostname0, "w+");
	   	fprintf(file_fwhostname2,"hostname2=NULL\n");
	   	rewind(file_fwhostname2);
	   	}

	   	char path_fwhostname3[100];
	   	sprintf(path_fwhostname3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.3", hostname);
	  	FILE *file_fwhostname3;
		file_fwhostname3 = fopen(path_fwhostname3, "r");
	   	char object_fwhostname3[100];

	 	if (file_fwhostname3 == NULL) {
	   	file_fwhostname3 = fopen(path_fwhostname3, "w+");
	   	fprintf(file_fwhostname3,"hostname3=NULL\n");
	   	rewind(file_fwhostname3);
	   	}

	   	char path_fwhostname4[100];
	   	sprintf(path_fwhostname4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.4", hostname);
	  	FILE *file_fwhostname4;
		file_fwhostname4 = fopen(path_fwhostname4, "r");
	   	char object_fwhostname4[100];

	 	if (file_fwhostname4 == NULL) {
	   	file_fwhostname4 = fopen(path_fwhostname4, "w+");
	   	fprintf(file_fwhostname4,"hostname4=NULL\n");
	   	rewind(file_fwhostname4);
	   	}

	   	char path_fwhostname5[100];
	   	sprintf(path_fwhostname5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.5", hostname);
	  	FILE *file_fwhostname5;
		file_fwhostname5 = fopen(path_fwhostname5, "r");
	   	char object_fwhostname5[100];

	 	if (file_fwhostname5 == NULL) {
	   	file_fwhostname5 = fopen(path_fwhostname5, "w+");
	   	fprintf(file_fwhostname5,"hostname5=NULL\n");
	   	rewind(file_fwhostname5);
	   	}

	   	char path_fwhostname6[100];
	   	sprintf(path_fwhostname6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.6", hostname);
	  	FILE *file_fwhostname6;
		file_fwhostname6 = fopen(path_fwhostname6, "r");
	   	char object_fwhostname6[100];

	 	if (file_fwhostname6 == NULL) {
	   	file_fwhostname6 = fopen(path_fwhostname6, "w+");
	   	fprintf(file_fwhostname6,"hostname6=NULL\n");
	   	rewind(file_fwhostname6);
	   	}

	   	char path_fwhostname7[100];
	   	sprintf(path_fwhostname7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.7", hostname);
	  	FILE *file_fwhostname7;
		file_fwhostname7 = fopen(path_fwhostname7, "r");
	   	char object_fwhostname7[100];

	 	if (file_fwhostname7 == NULL) {
	   	file_fwhostname7 = fopen(path_fwhostname7, "w+");
	   	fprintf(file_fwhostname7,"hostname7=NULL\n");
	   	rewind(file_fwhostname7);
	   	}

	   	char path_fwhostname8[100];
	   	sprintf(path_fwhostname8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.8", hostname);
	  	FILE *file_fwhostname8;
		file_fwhostname8 = fopen(path_fwhostname8, "r");
	   	char object_fwhostname8[100];

	 	if (file_fwhostname8 == NULL) {
	   	file_fwhostname8 = fopen(path_fwhostname8, "w+");
	   	fprintf(file_fwhostname8,"hostname8=NULL\n");
	   	rewind(file_fwhostname8);
	   	}

	   	char path_fwhostname9[100];
	   	sprintf(path_fwhostname9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.9", hostname);
	  	FILE *file_fwhostname9;
		file_fwhostname9 = fopen(path_fwhostname9, "r");
	   	char object_fwhostname9[100];

	 	if (file_fwhostname9 == NULL) {
	   	file_fwhostname9 = fopen(path_fwhostname9, "w+");
	   	fprintf(file_fwhostname9,"hostname9=NULL\n");
	   	rewind(file_fwhostname9);
	   	}

	   	char path_fwhostname10[100];
	   	sprintf(path_fwhostname10, "/home/user/ccndStatus-ObjectValues/%s.forwarding.hostname.10", hostname);
	  	FILE *file_fwhostname10;
		file_fwhostname10 = fopen(path_fwhostname10, "r");
	   	char object_fwhostname10[100];

	 	if (file_fwhostname10 == NULL) {
	   	file_fwhostname10 = fopen(path_fwhostname10, "w+");
	   	fprintf(file_fwhostname10,"hostname10=NULL\n");
	   	rewind(file_fwhostname10);
	   	}

	  	char path_fwtime0[100];
	  	sprintf(path_fwtime0, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.0", hostname);
	   	FILE *file_fwtime0;
	   	file_fwtime0 = fopen(path_fwtime0, "r");
	   	char object_fwtime0[100];

	 	if (file_fwtime0 == NULL) {
	   	file_fwtime0 = fopen(path_fwtime0, "w+");
	   	fprintf(file_fwtime0,"time0=NULL\n");
	   	rewind(file_fwtime0);
	   	}

	  	char path_fwtime1[100];
	  	sprintf(path_fwtime1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.1", hostname);
	   	FILE *file_fwtime1;
	   	file_fwtime1 = fopen(path_fwtime1, "r");
	   	char object_fwtime1[100];

	 	if (file_fwtime1 == NULL) {
	   	file_fwtime1 = fopen(path_fwtime1, "w+");
	   	fprintf(file_fwtime1,"time1=NULL\n");
	   	rewind(file_fwtime0);
	   	}

	  	char path_fwtime2[100];
	  	sprintf(path_fwtime2, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.2", hostname);
	   	FILE *file_fwtime2;
	   	file_fwtime2 = fopen(path_fwtime2, "r");
	   	char object_fwtime2[100];

	 	if (file_fwtime2 == NULL) {
	   	file_fwtime2 = fopen(path_fwtime2, "w+");
	   	fprintf(file_fwtime2,"time2=NULL\n");
	   	rewind(file_fwtime2);
	   	}

	  	char path_fwtime3[100];
	  	sprintf(path_fwtime3, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.3", hostname);
	   	FILE *file_fwtime3;
	   	file_fwtime3 = fopen(path_fwtime3, "r");
	   	char object_fwtime3[100];

	 	if (file_fwtime3 == NULL) {
	   	file_fwtime3 = fopen(path_fwtime3, "w+");
	   	fprintf(file_fwtime3,"time3=NULL\n");
	   	rewind(file_fwtime3);
	   	}

	  	char path_fwtime4[100];
	  	sprintf(path_fwtime4, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.4", hostname);
	   	FILE *file_fwtime4;
	   	file_fwtime4 = fopen(path_fwtime4, "r");
	   	char object_fwtime4[100];

	 	if (file_fwtime4 == NULL) {
	   	file_fwtime4 = fopen(path_fwtime4, "w+");
	   	fprintf(file_fwtime4,"time4=NULL\n");
	   	rewind(file_fwtime4);
	   	}

	  	char path_fwtime5[100];
	  	sprintf(path_fwtime5, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.5", hostname);
	   	FILE *file_fwtime5;
	   	file_fwtime5 = fopen(path_fwtime5, "r");
	   	char object_fwtime5[100];

	 	if (file_fwtime5 == NULL) {
	   	file_fwtime5 = fopen(path_fwtime5, "w+");
	   	fprintf(file_fwtime5,"time5=NULL\n");
	   	rewind(file_fwtime5);
	   	}

	  	char path_fwtime6[100];
	  	sprintf(path_fwtime6, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.6", hostname);
	   	FILE *file_fwtime6;
	   	file_fwtime6 = fopen(path_fwtime6, "r");
	   	char object_fwtime6[100];

	 	if (file_fwtime6 == NULL) {
	   	file_fwtime6 = fopen(path_fwtime6, "w+");
	   	fprintf(file_fwtime6,"time6=NULL\n");
	   	rewind(file_fwtime6);
	   	}

	  	char path_fwtime7[100];
	  	sprintf(path_fwtime7, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.7", hostname);
	   	FILE *file_fwtime7;
	   	file_fwtime7 = fopen(path_fwtime7, "r");
	   	char object_fwtime7[100];

	 	if (file_fwtime7 == NULL) {
	   	file_fwtime7 = fopen(path_fwtime7, "w+");
	   	fprintf(file_fwtime7,"time7=NULL\n");
	   	rewind(file_fwtime7);
	   	}

	  	char path_fwtime8[100];
	  	sprintf(path_fwtime8, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.8", hostname);
	   	FILE *file_fwtime8;
	   	file_fwtime8 = fopen(path_fwtime8, "r");
	   	char object_fwtime8[100];

	 	if (file_fwtime8 == NULL) {
	   	file_fwtime8 = fopen(path_fwtime8, "w+");
	   	fprintf(file_fwtime8,"time8=NULL\n");
	   	rewind(file_fwtime8);
	   	}

	  	char path_fwtime9[100];
	  	sprintf(path_fwtime9, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.9", hostname);
	   	FILE *file_fwtime9;
	   	file_fwtime9 = fopen(path_fwtime9, "r");
	   	char object_fwtime9[100];

	 	if (file_fwtime9 == NULL) {
	   	file_fwtime9 = fopen(path_fwtime9, "w+");
	   	fprintf(file_fwtime9,"time9=NULL\n");
	   	rewind(file_fwtime9);
	   	}

	  	char path_fwtime10[100];
	  	sprintf(path_fwtime1, "/home/user/ccndStatus-ObjectValues/%s.forwarding.time.10", hostname);
	   	FILE *file_fwtime10;
	   	file_fwtime10 = fopen(path_fwtime10, "r");
	   	char object_fwtime10[100];

	 	if (file_fwtime10 == NULL) {
	   	file_fwtime10 = fopen(path_fwtime10, "w+");
	   	fprintf(file_fwtime10,"time10=NULL\n");
	   	rewind(file_fwtime10);
	   	}

	////valores de cada objeto de ccndStatus/forwarding
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE0] = strdup (fgets (object_fwface0, sizeof(object_fwface0), file_fwface0)); fclose(file_fwface0);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE1] = strdup (fgets (object_fwface1, sizeof(object_fwface1), file_fwface1)); fclose(file_fwface1);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE2] = strdup (fgets (object_fwface2, sizeof(object_fwface2), file_fwface2)); fclose(file_fwface2);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE3] = strdup (fgets (object_fwface3, sizeof(object_fwface3), file_fwface3)); fclose(file_fwface3);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE4] = strdup (fgets (object_fwface4, sizeof(object_fwface4), file_fwface4)); fclose(file_fwface4);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE5] = strdup (fgets (object_fwface5, sizeof(object_fwface5), file_fwface5)); fclose(file_fwface5);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE6] = strdup (fgets (object_fwface6, sizeof(object_fwface6), file_fwface6)); fclose(file_fwface6);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE7] = strdup (fgets (object_fwface7, sizeof(object_fwface7), file_fwface7)); fclose(file_fwface7);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE8] = strdup (fgets (object_fwface8, sizeof(object_fwface8), file_fwface8)); fclose(file_fwface8);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE9] = strdup (fgets (object_fwface9, sizeof(object_fwface9), file_fwface9)); fclose(file_fwface9);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFACE10] = strdup (fgets (object_fwface10, sizeof(object_fwface10), file_fwface10)); fclose(file_fwface10);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS0] = strdup (fgets (object_fwflags0, sizeof(object_fwflags0), file_fwflags0)); fclose(file_fwflags0);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS1] = strdup (fgets (object_fwflags1, sizeof(object_fwflags1), file_fwflags1)); fclose(file_fwflags1);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS2] = strdup (fgets (object_fwflags2, sizeof(object_fwflags2), file_fwflags2)); fclose(file_fwflags2);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS3] = strdup (fgets (object_fwflags3, sizeof(object_fwflags3), file_fwflags3)); fclose(file_fwflags3);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS4] = strdup (fgets (object_fwflags4, sizeof(object_fwflags4), file_fwflags4)); fclose(file_fwflags4);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS5] = strdup (fgets (object_fwflags5, sizeof(object_fwflags5), file_fwflags5)); fclose(file_fwflags5);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS6] = strdup (fgets (object_fwflags6, sizeof(object_fwflags6), file_fwflags6)); fclose(file_fwflags6);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS7] = strdup (fgets (object_fwflags7, sizeof(object_fwflags7), file_fwflags7)); fclose(file_fwflags7);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS8] = strdup (fgets (object_fwflags8, sizeof(object_fwflags8), file_fwflags8)); fclose(file_fwflags8);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS9] = strdup (fgets (object_fwflags9, sizeof(object_fwflags9), file_fwflags9)); fclose(file_fwflags9);
		ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWFLAGS10] = strdup (fgets (object_fwflags10, sizeof(object_fwflags10), file_fwflags10)); fclose(file_fwflags10);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH0] = strdup (fgets (object_fwpath0, sizeof(object_fwpath0), file_fwpath0)); fclose(file_fwpath0);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH1] = strdup (fgets (object_fwpath1, sizeof(object_fwpath1), file_fwpath1)); fclose(file_fwpath1);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH2] = strdup (fgets (object_fwpath2, sizeof(object_fwpath2), file_fwpath2)); fclose(file_fwpath2);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH3] = strdup (fgets (object_fwpath3, sizeof(object_fwpath3), file_fwpath3)); fclose(file_fwpath3);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH4] = strdup (fgets (object_fwpath4, sizeof(object_fwpath4), file_fwpath4)); fclose(file_fwpath4);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH5] = strdup (fgets (object_fwpath5, sizeof(object_fwpath5), file_fwpath5)); fclose(file_fwpath5);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH6] = strdup (fgets (object_fwpath6, sizeof(object_fwpath6), file_fwpath6)); fclose(file_fwpath6);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH7] = strdup (fgets (object_fwpath7, sizeof(object_fwpath7), file_fwpath7)); fclose(file_fwpath7);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH8] = strdup (fgets (object_fwpath8, sizeof(object_fwpath8), file_fwpath8)); fclose(file_fwpath8);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH9] = strdup (fgets (object_fwpath9, sizeof(object_fwpath9), file_fwpath9)); fclose(file_fwpath9);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWPATH10] = strdup (fgets (object_fwpath10, sizeof(object_fwpath10), file_fwpath10)); fclose(file_fwpath10);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES0] = strdup (fgets (object_fwexpires0, sizeof(object_fwexpires0), file_fwexpires0)); fclose(file_fwexpires0);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES1] = strdup (fgets (object_fwexpires1, sizeof(object_fwexpires1), file_fwexpires1)); fclose(file_fwexpires1);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES2] = strdup (fgets (object_fwexpires2, sizeof(object_fwexpires2), file_fwexpires2)); fclose(file_fwexpires2);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES3] = strdup (fgets (object_fwexpires3, sizeof(object_fwexpires3), file_fwexpires3)); fclose(file_fwexpires3);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES4] = strdup (fgets (object_fwexpires4, sizeof(object_fwexpires4), file_fwexpires4)); fclose(file_fwexpires4);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES5] = strdup (fgets (object_fwexpires5, sizeof(object_fwexpires5), file_fwexpires5)); fclose(file_fwexpires5);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES6] = strdup (fgets (object_fwexpires6, sizeof(object_fwexpires6), file_fwexpires6)); fclose(file_fwexpires6);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES7] = strdup (fgets (object_fwexpires7, sizeof(object_fwexpires7), file_fwexpires7)); fclose(file_fwexpires7);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES8] = strdup (fgets (object_fwexpires8, sizeof(object_fwexpires8), file_fwexpires8)); fclose(file_fwexpires8);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES9] = strdup (fgets (object_fwexpires9, sizeof(object_fwexpires9), file_fwexpires9)); fclose(file_fwexpires9);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWEXPIRES10] = strdup (fgets (object_fwexpires10, sizeof(object_fwexpires10), file_fwexpires10)); fclose(file_fwexpires10);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST0] = strdup (fgets (object_fwhostname0, sizeof(object_fwhostname0), file_fwhostname0)); fclose(file_fwhostname0);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST1] = strdup (fgets (object_fwhostname1, sizeof(object_fwhostname1), file_fwhostname1)); fclose(file_fwhostname1);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST2] = strdup (fgets (object_fwhostname2, sizeof(object_fwhostname2), file_fwhostname2)); fclose(file_fwhostname2);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST3] = strdup (fgets (object_fwhostname3, sizeof(object_fwhostname3), file_fwhostname3)); fclose(file_fwhostname3);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST4] = strdup (fgets (object_fwhostname4, sizeof(object_fwhostname4), file_fwhostname4)); fclose(file_fwhostname4);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST5] = strdup (fgets (object_fwhostname5, sizeof(object_fwhostname5), file_fwhostname5)); fclose(file_fwhostname5);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST6] = strdup (fgets (object_fwhostname6, sizeof(object_fwhostname6), file_fwhostname6)); fclose(file_fwhostname6);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST7] = strdup (fgets (object_fwhostname7, sizeof(object_fwhostname7), file_fwhostname7)); fclose(file_fwhostname7);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST8] = strdup (fgets (object_fwhostname8, sizeof(object_fwhostname8), file_fwhostname8)); fclose(file_fwhostname8);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST9] = strdup (fgets (object_fwhostname9, sizeof(object_fwhostname9), file_fwhostname9)); fclose(file_fwhostname9);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWHOST10] = strdup (fgets (object_fwhostname10, sizeof(object_fwhostname10), file_fwhostname10)); fclose(file_fwhostname10);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP0] = strdup (fgets (object_fwtime0, sizeof(object_fwtime0), file_fwtime0)); fclose(file_fwtime0);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP1] = strdup (fgets (object_fwtime1, sizeof(object_fwtime1), file_fwtime1)); fclose(file_fwtime1);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP2] = strdup (fgets (object_fwtime2, sizeof(object_fwtime2), file_fwtime2)); fclose(file_fwtime2);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP3] = strdup (fgets (object_fwtime3, sizeof(object_fwtime3), file_fwtime3)); fclose(file_fwtime3);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP4] = strdup (fgets (object_fwtime4, sizeof(object_fwtime4), file_fwtime4)); fclose(file_fwtime4);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP5] = strdup (fgets (object_fwtime5, sizeof(object_fwtime5), file_fwtime5)); fclose(file_fwtime5);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP6] = strdup (fgets (object_fwtime6, sizeof(object_fwtime6), file_fwtime6)); fclose(file_fwtime6);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP7] = strdup (fgets (object_fwtime7, sizeof(object_fwtime7), file_fwtime7)); fclose(file_fwtime7);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP8] = strdup (fgets (object_fwtime8, sizeof(object_fwtime8), file_fwtime8)); fclose(file_fwtime8);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP9] = strdup (fgets (object_fwtime9, sizeof(object_fwtime9), file_fwtime9)); fclose(file_fwtime9);
	   	ccnMibStatusForwardingObjectValue[CCN_STATUS_FORWARDING_OBJECT_FWTIMESTAMP10] = strdup (fgets (object_fwtime10, sizeof(object_fwtime10), file_fwtime10)); fclose(file_fwtime10);
}

//Rodar como daemon em background
static void daemonize(void)
{
    pid_t pid;
    pid = fork();

    // In case of fork is error.
    if (pid < 0) {
        fprintf(stderr, "fork failed: %d", errno);
        exit(-1);
    }

    // In case of this is parent process.
    if (pid != 0)
        exit(0);

    // Become session leader and get pid.
    pid = setsid();

    if (pid == -1) {
        fprintf(stderr, "setsid failed: %d", errno);
        exit(-1);
    }

    // Change directory to root.
    if (chdir("/") < 0)
        exit(-1);

    // File descriptor close.
    if (!freopen("/dev/null", "r", stdin) ||
        !freopen("/dev/null", "w", stdout) ||
        !freopen("/dev/null", "w", stderr))
        exit(-1);

    umask(0027);
}

//Vai mapear o pacote Interest em um valor de resposta

int construct_ping_response(struct ccn *h, struct ccn_charbuf *data, 
        const unsigned char *interest_msg, const struct ccn_parsed_interest *pi, int expire, int parentObject, int object)
{
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    int res = 0;

    updateMibObjectValue();

    ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
            pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);


    // Set freshness seconds.
    if (expire >= 0) {
        sp.template_ccnb = ccn_charbuf_create();
        ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
        ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%ld", expire);
        sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
        ccn_charbuf_append_closer(sp.template_ccnb);

    }

    if (parentObject == CCN_PARENT_OBJECT_SYSTEM)
    	res = ccn_sign_content(h, data, name, &sp, ccnMibSystemObjectValue[object], strlen(ccnMibSystemObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS)
    	res = ccn_sign_content(h, data, name, &sp, ccnMibStatusContentItemsObjectValue[object], strlen(ccnMibStatusContentItemsObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_INTERESTS)
    	res = ccn_sign_content(h, data, name, &sp, ccnMibStatusInterestsObjectValue[object], strlen(ccnMibStatusInterestsObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS)
        res = ccn_sign_content(h, data, name, &sp, ccnMibStatusInterestTotalsObjectValue[object], strlen(ccnMibStatusInterestTotalsObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_FACES)
        res = ccn_sign_content(h, data, name, &sp, ccnMibStatusFacesObjectValue[object], strlen(ccnMibStatusFacesObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES)
        res = ccn_sign_content(h, data, name, &sp, ccnMibStatusfaceActivityRatesObjectValue[object], strlen(ccnMibStatusfaceActivityRatesObjectValue[object]));
    else if (parentObject == CCN_PARENT_OBJECT_STATUS_FORWARDING)
        res = ccn_sign_content(h, data, name, &sp, ccnMibStatusForwardingObjectValue[object], strlen(ccnMibStatusForwardingObjectValue[object]));

    ccn_charbuf_destroy(&sp.template_ccnb);
    ccn_charbuf_destroy(&name);

    return res;
}

//Assinatura padrão do CCNx para processar um pacote Interest

enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
    struct ccn_ping_server *server = selfp->data;
    int res;
    struct ccn_indexbuf *prefix_components;
    int prefix_ncomps;
    const unsigned char *comp = NULL, parent_comp[256];
    size_t size;
    int parentObject = -1, object = -1, i = 0, ret[CCN_MAX_PARENT_OBJECTS];

    switch (kind) {
        case CCN_UPCALL_FINAL:
            break;
        case CCN_UPCALL_INTEREST:
//        	if (ping_interest_valid(server->prefix, info->interest_ccnb, info->pi)) {
        		prefix_components = ccn_indexbuf_create();
        		prefix_ncomps = ccn_name_split(server->prefix, prefix_components);
        		ccn_indexbuf_destroy(&prefix_components);

        		memset(parent_comp, 0, 256);
        		printf("prefix_ncomps = %d; pi_prefix_comps = %d\n", prefix_ncomps, info->pi->prefix_comps);
        		for (i=prefix_ncomps; i<(info->pi->prefix_comps - 2); i++)
        		{
        			printf("ccn_name_comp_get = %d\n",
        					ccn_name_comp_get(info->interest_ccnb, info->interest_comps, i, &comp, &size));
        			if (comp != NULL)
        			{
        				printf("p_object = %s; size = %d\n", comp, (int)size);
        				if (i != prefix_ncomps)
        					strncat(parent_comp, "/", (256 - strlen(parent_comp)));
        				strncat(parent_comp, comp, (256 - strlen(parent_comp)));
        			}
        		}
        		printf("ccn_name_comp_get = %d\n",
        				ccn_name_comp_get(info->interest_ccnb, info->interest_comps, (info->pi->prefix_comps - 2), &comp, &size));
        		if (comp != NULL) printf("object = %s; size = %d\n", comp, (int)size);
        		printf("parent_comp = %s\n", parent_comp);
        		for (i=0; i<=strlen(parent_comp); i++) printf("[0x%X] ", parent_comp[i]);
        		printf("\n");

        		// get parent object and object
        		//ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps, &comp, &size);
        		if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_SYSTEM],
        				MAX(strlen(parent_comp),strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_SYSTEM]))) == 0)
        		{
        			parentObject = CCN_PARENT_OBJECT_SYSTEM;
        			//ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        			for (i=0; i<CCN_SYSTEM_MAX_OBJECTS; i++)
        			{
        				printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibSystemObjectName[i]);
        				if (strncmp(comp, ccnMibSystemObjectName[i],
        						MAX(size, strlen(ccnMibSystemObjectName[i]))) == 0)
        				{
        					object = i;
        					printf("Found (%d)\n", i);
        					break;
        				}
        			}
        		}
        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS],
        				MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS]))) == 0)
        		{
        			parentObject = CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS;
        			//ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        			for (i=0; i<CCN_STATUS_CONTENT_ITEMS_MAX_OBJECTS; i++)
        			{
        				printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusContentItemsObjectName[i]);
        				if (strncmp(comp, ccnMibStatusContentItemsObjectName[i],
        						MAX(size, strlen(ccnMibStatusContentItemsObjectName[i]))) == 0)
        				{
        					object = i;
        					printf("Found (%d)\n", i);
        					break;
        				}
        			}
        		}
        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTERESTS],
        				MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTERESTS]))) == 0)
        		{
        			parentObject = CCN_PARENT_OBJECT_STATUS_INTERESTS;
        			//ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        			for (i=0; i<CCN_STATUS_INTERESTS_MAX_OBJECTS; i++)
        			{
        				printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusInterestsObjectName[i]);
        				if (strncmp(comp, ccnMibStatusInterestsObjectName[i],
        						MAX(size, strlen(ccnMibStatusInterestsObjectName[i]))) == 0)
        				{
        					object = i;
        					printf("Found (%d)\n", i);
        					break;
        				}
        			}
        		}

        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS],
        		        				MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS]))) == 0)
        		{
        		    parentObject = CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS;
        		    //ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        		    for (i=0; i<CCN_STATUS_INTEREST_TOTALS_MAX_OBJECTS; i++)
        		    {
        		        printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusInterestTotalsObjectName[i]);
        		        if (strncmp(comp, ccnMibStatusInterestTotalsObjectName[i],
        		        		MAX(size, strlen(ccnMibStatusInterestTotalsObjectName[i]))) == 0)
        		        {
        		        	object = i;
        		        	printf("Found (%d)\n", i);
        		        	break;
        		        }
        		     }
        		}

        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACES],
        		        		        MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACES]))) == 0)
        		{
        		     parentObject = CCN_PARENT_OBJECT_STATUS_FACES;
        		     //ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        		     for (i=0; i<CCN_STATUS_FACES_MAX_OBJECTS; i++)
        		     {
        		         printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusFacesObjectName[i]);
        		        if (strncmp(comp, ccnMibStatusFacesObjectName[i],
        		        		    MAX(size, strlen(ccnMibStatusFacesObjectName[i]))) == 0)
        		        {
        		        	object = i;
        		        	printf("Found (%d)\n", i);
        		        	break;
        		        }
        		     }
        		}

        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES],
        		        		    MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES]))) == 0)
        		{
        		      parentObject = CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES;
        		      //ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        		      for (i=0; i<CCN_STATUS_FACE_ACTIVITY_RATES_MAX_OBJECTS; i++)
        		      {
        		        printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusfaceActivityRatesObjectName[i]);
        		        if (strncmp(comp, ccnMibStatusfaceActivityRatesObjectName[i],
        		        		    MAX(size, strlen(ccnMibStatusfaceActivityRatesObjectName[i]))) == 0)
        		        {
        		        	object = i;
        		        	printf("Found (%d)\n", i);
        		        	break;
        		        }
        		     }
        		}

        		else if (strncmp(parent_comp, ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FORWARDING],
        		        		        		    MAX(strlen(parent_comp), strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FORWARDING]))) == 0)
        		        		{
        		        		      parentObject = CCN_PARENT_OBJECT_STATUS_FORWARDING;
        		        		      //ccn_name_comp_get(info->interest_ccnb, info->interest_comps, prefix_ncomps + 1, &comp, &size);
        		        		      for (i=0; i<CCN_STATUS_FORWARDING_MAX_OBJECTS; i++)
        		        		      {
        		        		        printf("Checking match: interest = %s; object %d = %s\n", comp, i, ccnMibStatusForwardingObjectName[i]);
        		        		        if (strncmp(comp, ccnMibStatusForwardingObjectName[i],
        		        		        		    MAX(size, strlen(ccnMibStatusForwardingObjectName[i]))) == 0)
        		        		        {
        		        		        	object = i;
        		        		        	printf("Found (%d)\n", i);
        		        		        	break;
        		        		        }
        		        		     }
        		        		}

        		else
        		{
        			printf("Parent object %s (size %d) did not match %s (size %d), %s (size %d), %s (size %d), %s (size %d), %s (size %d), %s (size %d) or %s (size %d)\n",
        					parent_comp,
							strlen(parent_comp),
							ccnMibParentObjectName[CCN_PARENT_OBJECT_SYSTEM],
							strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_SYSTEM]),
							ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS],
							strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_CONTENT_ITEMS]),
							ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTERESTS],
							strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTERESTS]),
        					ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS],
        					strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_INTEREST_TOTALS]),
        					ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACES],
        			        strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACES]),
        					ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES],
        			        strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FACE_ACTIVITY_RATES]),
        					ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FORWARDING],
        			        strlen(ccnMibParentObjectName[CCN_PARENT_OBJECT_STATUS_FORWARDING]));
        		}

        		// Construct Data content with given Interest name.
        		if (parentObject == -1)
        		{
        			printf("Invalid parent object\n");
        		}
        		else if (object == -1)
        		{
        			printf("Invalid object\n");
        		}
        		else
        		{
        			struct ccn_charbuf *data = ccn_charbuf_create();
        			construct_ping_response(info->h, data, info->interest_ccnb,
        					info->pi, server->expire, parentObject, object);

        			res = ccn_put(info->h, data->buf, data->length);
        			ccn_charbuf_destroy(&data);
        		}

        		server->count ++;

        		if (res >= 0)
        			return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
//        	}
        	break;
        default:
        	break;
    }

    return CCN_UPCALL_RESULT_OK;

}

int main(int argc, char* argv[])

{
  struct ccn *ccn = NULL;
  struct ccn_ping_server server = {.count = 0, .expire = 1};
  struct ccn_closure in_interest = {.p = &incoming_interest};
    int res;
    int daemon_mode = 0;
    char prefix[32];


    server.prefix = ccn_charbuf_create();

    if (argc == 2)
    	snprintf(prefix, 32, "ccnx:/%s/", (char *)argv[1]);
    else
    	snprintf(prefix, 32, "ccnx:/%s/", (char *) getenv("NE_NAME"));

//    if (argc == 2)
//        	snprintf(prefix, 32, "ccnx:/%s/", (char *)argv[1]);
//        else
//        	snprintf(prefix, 32, "ccnx:/NE/");

    printf("Prefix: %s.\n", prefix);
    res = ccn_name_from_uri(server.prefix, prefix);

    if (res < 0) {
        fprintf(stderr, "erro\n");
        exit(1);
    }

    initializeMibObjectValue();


    //Commented by Marciel (string "ping" removed from Interest packet name)

    // Append "/ping" to the given name prefix.
    //res = ccn_name_append_str(server.prefix, PING_COMPONENT);
   // if (res < 0) {
    //    fprintf(stderr, "%s: error constructing ccn URI: %s/%s\n",
   //             progname, argv[0], PING_COMPONENT);
   //     exit(1);
  //  }

//    initializeMibSystemObjectValueArray();

    // Connect to ccnd.
    ccn = ccn_create();
    if (ccn_connect(ccn, NULL) == -1) {
        perror("Could not connect to ccnd");
        exit(1);
    }

    in_interest.data = &server;
    res = ccn_set_interest_filter(ccn, server.prefix, &in_interest);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }


     if (daemon_mode)
        daemonize();

    res = ccn_run(ccn, -1);

    ccn_destroy(&ccn);
    ccn_charbuf_destroy(&server.prefix);


    return 0;
}
