# SNMP Gateway CCN

## Tutorial

#### What is SNMP Gateway CCN?

SNMP Gateway CCN is a tool for management CCN (Content-Centric Network) nodes through the SNMP gateway. The gateway translates *SNMP Request* messages to CCNx *Interest* messages, then send to CCN network for native routing mechanism based on name/data. When a message arrives at the destination node, one *Data* message as a response is built for each request and the messages are sent on the opposite way to the gateway. The gateway translates the message *Data* to *SNMP Response* message and delivery to NMS Server.

#### Environment versions 
- Linux Ubuntu 15.04 64bits (Vivid Vervet)
- InuxDB v0.9.2
- Inuxdb-python (0.1.12-1)
- Mininet 2.2.0b1
- CCNx v0.8.2
- Net-SNMP v5.7.2
- SnmpB v0.8 (MIB Browser)
- Wireshark v1.6.2

#### PC Specifications for Virtual Machine
- VMware Workstation 12 Player
- Windows 7 or Windows 10 64 bits
- Intel Core i5-2450M CPU 2.5GHz
- 8GB RAM

#### Acess Linux Virtual Machine

```
# Login: user
# Passwd: user
``` 

#### Make sure that influxdb was started. 

If is necessary, start influxDB according following command line.

```
# sudo /etc/init.d/influxdb start  
``` 

#### SNMP Gateway CCN running on MiniCCNx platform

To start SNMP Gateway CCN is necessary to open tool MiniccnxEdit (graphical front-end for MiniCCNx platform) according follow command line.

```
# sudo miniccnxedit
# passwd: user
``` 

The window below will be open.

![fig1](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig1.jpg)

#### Openning the topology

Reference topology was built with all environment settings for 10 nodes and saved into config file to reload when necessary. Inorder to open config file, just click on menu *File->Open* and select config file *.mnccnx.

![fig2](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig2.jpg)

#### Starting topology

To starting topology just click on *Run* button on the lower corner left. 

![fig3](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig3.jpg)

#### Reference topology 

The reference topology was built with 10 nodes, distributed on ring topology and some linear remote nodes. Each node has a name with **r** (router) plus number *1-10*.  

![fig4](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig4.jpg)

#### Starting CCN Agent 

The CCN Agent has started automatically on each CCN node during MiniCCNx topology starting. 

It is possible to verify all instances CCN Agent that are running on each CCN node by the follow command line in any CCN node container.

```
# ps -aux | grep ccna 
```  

Command line results show on screenshot bellow. 

![fig5](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig5.jpg)


#### Starting SNMP Agent on network element gateway (r1)

The SNMP Agent represents gateway between NMS and CCN Network is based on Net-SNMP v5.7.2 application that was compiled to mapping CCN MIB OIDs.

First of all, the Net-SNMP shall be installed and setting up according to config file *snmpd.conf* as a bellow.

```
**snmpd.conf :**
##############################
rwuser user123456 (SNMPv3 write credentials)
rouser user123456 (SNMPv3 read credentials)
rwcommunity private (SNMPv1 and SNMPv2 write credentials)
rocommunity public (SNMPv1 and SNMPv2 read credentials)
##############################
```

To start SNMP Agent is necessary to run script **snmp-gateway-ccn_start** on r1 node, according follow command line.

```
# ./snmp-gateway-ccn_start
```  

The script will start the snmpd daemon on gateway node, as showing on screenshot bellow.

![fig6](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig6.jpg)


#### Starting MIB Browser SnmpB

The SnmB tool is used to load CCN MIB that allow generating SNMP Requests (eg.: GET, GET-NEXT, GET-BULK, WALK), in this context SnmpB tool works as an NMS Server. 

Starting SnmpB tool on gateway r1 node by command line bellow.

```
# sudo snmpb
```  

![fig7](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig7.jpg)

#### Setting MIB Browser SnmpB and loading CCN MIB

SnmpB tool shall be setting to communicate with SNMP Agent and load the CCN MIB to allow requests ccnSystem and ccndStatus objects. The contextName field of SNMPv3 protocol is used to identify the CCN node that wants to monitor, therefore is necessary set the SnmpB with SNMPv3 version.

SnmpB tool completed fields step by step.

**Agent Profiles:** access Options->Agent Profiles.\
**Name:** localhost (to access snmp agente on gateway)\
**Agent/Address Name:** 127.0.0.1 (localhost address gateway)\
**Agent port:** 161 (agent snmp port default)\
**Retries:** 1 (number of retries requests)\
**Timeout:** (timeout to operation abort)\
**Supported SNMP Version:** SNMPv3 (SNMP version 3 support)

![fig8](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig8.jpg)

**Get-Bulk:** acesse Options->Agent Profiles->Get-Bulk.\
**Non repeaters:** 0 (number of repetitions)\
**Max repetitions:** 7 (numeber of OIDs requests)

![fig9](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig9.jpg)

- SNMPv3 User (USM)\
**Security Name:** user (user name)\
**Security Level:** authNoPriv (with user authentication, without encryption messages)
- SNMPv3 context\
**Context Name:** r + number of node (number of nodes that is want to consult)\
Context Engine ID: (keep this field in blank)

![fig10](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig10.jpg)

**USM Profiles:** access Options->Manage SNMPv3 USM Profiles.
- User\
**Security User Name:** user (user name)
- Security\
**Authentication Protocol:** MD5 (algorithm to encrypt user authentication)\
Authentication Password: user (password user)\
Privacy Protocol: none (encrypt messages, disable)\
Privacy Password: (keep this field in blank)

![fig11](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig11.jpg)

**Modules:** acesse Options->Preferences->Modules.
Click on Add button to add the path of the CCN MIB.

![fig12](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig12.jpg)

In the SnmpB main window access the tab Modules and looking for CCN MIB on window Load MIB Modules. 

![fig13](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig13.jpg)

#### Accessing CCN MIB on SnmpB MIB Browser

In the SnmpB main window access MIB Tree->iso->org->dod->internet->mgmt->mib2->ccnMIB.

![fig14](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig14.jpg)

#### SNMP Gateway CCN started

The SNMP Gateway CCN started and ready to consult CCN nodes!

![fig15](https://github.com/marcieloliveira/snmp-gateway-ccn/blob/master/screenshot/fig15.jpg)

## SNMP Gateway CCN presentation

Watch a brief presentation of tool, access link below.
https://youtu.be/vIfCsDhPoS0

## Contacts

Contact the main author Marciel Oliveira (marciel.oliveira@gmail.com) or Prof. Christian Esteve Rothenberg (chesteve@dca.fee.unicamp.br).




