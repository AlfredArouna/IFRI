#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Hospice Alfred
#
# This file is part of Network Administration Visualized (NAV).
#
# NAV is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.  You should have received a copy of the GNU General Public
# License along with NAV. If not, see <http://www.gnu.org/licenses/>.
#


import nav.Snmp
from nav import buildconf
import threading
#import sys
import datetime
import os
import IPy
import logging
import signal


LOGFILE_NAME = 'autoseeddb.log'
LOGFILE_PATH = os.path.join(buildconf.localstatedir, 'log', LOGFILE_NAME)


class SeedDb():
    u"""
    Initialize input parameters
    """
    def __init__(self):
        u"""Prompt SNMP version selection to user.
        Base on user selection, call the corresponding version of SNMP Api.
        """

        # logging
        try:
            logging.basicConfig(
            filename=LOGFILE_PATH,
            format='[ %(asctime)s ][ %(levelname)-8s ] %(name)s - %(message)s',
            level=logging.DEBUG)
            logging.debug('')
            logging.info(u"""Starting SeedDB: NAV SNMP based \
            Network Host Discovery""")
        except:
            print
            print "Error: could not read log file."
            print "Maybe you can run as root ?"
            print "Exiting..."
            print
            exit(1)
        #print chr(27) + "[2J"
        print
        print "========================================================"
        print "=== Welcome to NAV SNMP based Network Host Discovery ==="
        print "========================================================"
        print

        #MIBs list
        self.sys_service = "1.3.6.1.2.1.1.7"

        self.ip_forwarding = "1.3.6.1.2.1.4.1"

        self.dot1d_bridge = "1.3.6.1.2.1.17"

        self.my_room = "myroom"
        self.my_org = "myorg"

        # prompt starting ip
        seed_router = raw_input("Enter starting router IP: ").decode("utf-8")
        logging.info('Getting seed_router IP:  %s', seed_router)
        # check ip validity
        try:
            logging.info('Checking seed_router IP:  %s', seed_router)
            IPy.IP(seed_router)
            print "[OK] seed_router..."
        except:
            print
            print u"IP address " + seed_router + " is invalid"
            print u"Exiting...."
            print
            logging.error('Invalid seed_router IP:  %s', seed_router)
            logging.error('Exiting...')
            exit(1)

        logging.info('Getting SNMP version')
        print u"=============================================="
        print u"==== Select SNMP version for your Network ===="
        print u"==== 1 for SNMP v1                        ===="
        print u"==== 2 for all versions of SNMP v2        ===="
        print u"==== 3 for SNMP v3                        ===="
        print u"=============================================="

        u""" Get user selection """
        version = raw_input().decode("utf-8")
        #print version

        logging.info('Checking SNMP parameters for SNMPv%s in seed_router %s',
            version, seed_router)
        if version == "1":
            #print "Old version 1"
            self.request_snmp_parameters(1, seed_router)
        elif version == "2":
            #print "All v2 version"
            self.request_snmp_parameters(2, seed_router)
        elif version == "3":
            #print "More secure version"
            self.request_snmp_parameters(3, seed_router)
        else:
            print
            print (u"Hum! i don't know version %s of SNMP") % (version)
            print (u"May be you can make a RFC for SNMPv%s") % (version)
            print u"Exiting...."
            print
            logging.error('Unknow SNMP version %s', version)
            exit(1)

    def request_snmp_parameters(self, version, seed_router):
        u"""
        Base on SNMP version, call corresponding function to check SNMP
        status on given host ip. v1 and v2 still in the same logic. SNMPv3
        required additionnals parameters.
        """
        if version == 1:
            community = raw_input("Enter community for version 1: ")
            if self.check_snmp(seed_router, 1, community=community):
                print
                print "[OK] SNMP parameters..."
                print
                logging.info('Starting device discovery for router %s',
                     seed_router)
                print "Starting device discovery"
                self.device_discovery(seed_router, 1, community=community)
            else:
                print
                print (u"""Error: seems like router %s did not support \
                SNMPv%s or may be community %s is invalid""") % (seed_router,
                version, community)
                print
                logging.error(u"""Router %s did not support SNMPv%s or may be\
                community %s is invalid""", seed_router, version, community)
                exit(1)

        elif version == 2:
            community = raw_input("Enter community for version 2: ")
            print
            print "Checking SNMP parameters..."
            if self.check_snmp(seed_router, 2, community=community):
                print
                print "[OK] SNMP parameters..."
                logging.info(u"""Starting device discovery for router \
                %s """, seed_router)
                print "Starting device discovery"
                self.device_discovery(seed_router, 2, community=community)
            else:
                print
                print (u"""Error: seems like router %s did not support \
                SNMPv%s or may be community %s is invalid""") % (seed_router,
                version, community)
                print
                logging.error("""Router %s did not support SNMPv%s \
                or may be community %s is invalid""", seed_router,
                version, community)
                exit(1)

        elif version == 3:
            print
            print u"Not yet implemented"
            logging.info('Exiting on SNMPv%s choice', version)
            exit(0)
            u"""
            print "SNMPv3 parameters: "
            username = raw_input("Enter username: ")
            print "Select security level: "
            print "    1 for noAuthnoPriv     "
            print "    2 for authnoPriv       "
            print "    3 for authPriv         "
            level = raw_input()
            securityLevel=self.get_security_level(level)
            print "Select authentifiaction protocol: "
            print "    1 MD5     "
            print "    2 SHA       "
            authen = raw_input()
            authProto=self.get_authen_proto(authen)
            password = raw_input("Enter password: ")
            print "Select privacy protocol: "
            print "    1 DES     "
            print "    2 AES       "
            privacy = raw_input()
            pricacyProto=self.get_privacy_proto(privacy)
            passphrase = raw_input("Enter privacy passphrase: ")

            if self.check_snmp(seed_router, 3, username=username,
                securityLevel=securityLevel,
                authProto=authProto,
                password=password,
                pricacyProto=pricacyProto,
                passphrase=passphrase):
                print "Ok, let's go!"
            else:
                print (u"Error: seems like router %s did not support SNMP "
                "or may be security parameters are invalid. "
                "Username: %s "
                "Security Level: %s "
                "Authentification Protocol: % s "
                "Password: %s "
                "Privacy Protocol: %s "
                "Passphrase: %s ") % (seed_router,username,securityLevel,
                authProto,password,pricacyProto,passphrase)
            """

    # check seed_router answer to SNMP get request
    def check_snmp(self, ip, version, **kwarg):
        u"check if SNMP getRequest has valid result from seed_router"
        if version == 1 or version == 2:
            s = nav.Snmp.Snmp(ip, kwarg['community'], version)
            try:
                if s.get():
                    return True
                else:
                    return False
            except:
                    return False
        elif version == 3:
            print kwarg['authProto']

    def device_discovery(self, ip, version, **kwarg):
        u"get all device on the network using SNMP"
        # Create devices liste
        devices = []
        # Add seed router to routers list
        devices.append(ip)
        community = kwarg['community']

        lock = threading.Lock()
        #print routers
        u"""Device discovery using next hop mechanism.
        Only routers are get."""
        print
        print "Getting all routers on the network"

        # loop on devices array to get SNMP ip_route_next_hop
        # which are indirect
        for r in devices:
            # create SNMP object
            logging.info('Create SNMPv%s object for router %s', version, r)
            sn = nav.Snmp.Snmp(r, community, version)
            # get ip_route_next_hop
            logging.info('Getting IndirectNextHop from router %s', r)
            get_indirect_next_hop = GetIndirectNextHop(lock, sn, r, devices,
            version, community=community)
            get_indirect_next_hop.start()
            get_indirect_next_hop.join()

        # get devices (routers) list
        #print "Routers list: "
        #print devices
        print
        print "[OK] Routers list..."
        logging.info('All routers list %s', devices)

        u"""
        Device discovery using ARP cache entries.
        Add local network device to devices array.
        """

        print
        print "Getting all Hosts on the network"
        get_local_net_address = GetLocalNetAddress(lock, devices,
        version, community=community)
        get_local_net_address.start()
        get_local_net_address.join()

        # get all network devices list
        print
        #print "All network unique devices list: "
        #print devices
        print "[OK] All devices list..."
        logging.info('All devices list %s', devices)

        u"""
        Device type discovery using sys_service,
        dot1d_bridge, ip_forwarding MIBs
        """

        print
        print "Setting all network Host type"
        host_type_list = self.get_device_type(devices, version,
        community=community)

        # get all network devices  type list
        print
        #print "All network unique devices  type list: "
        #print host_type_list
        print "[OK] Device type..."
        logging.info('All device type %s', host_type_list)

        print
        print "Creating bulk import file"
        bulk_list = self.create_bulk_format(host_type_list,
        version, community=community)
        # get bulk format
        print
        #print "Bulk format"
        #print bulk_list
        print (u"[OK] Create bulk import file: %s") % (bulk_list)
        print "Exiting..."
        print
        logging.info('Create bulk import file: %s', bulk_list)

        logging.info('Exiting at the end of the script...')
        exit(0)

    def get_device_type(self, devices, version, **kwarg):
        u"Get device type base on SNMP services"
        community = kwarg['community']
        host_type = []
        for host in devices:
            sn = nav.Snmp.Snmp(host, kwarg['community'], version)
            logging.info(u"""Create SNMP object for device %s
            for device  type discovery""", host)
            try:
                if sn.walk(sys_service):
                    [(service_oid, host_service_id)] = sn.walk(
                    self.sys_service)
                    if host_service_id == 78:
                        host_type.append([host, 'GW'])
                        logging.info('Setting device %s as ROUTER', host)
                    elif host_service_id == 72:
                        if sn.walk(ip_forwarding):
                            [(forward_oid, host_forward_id)] = sn.walk(
                            self.ip_forwarding)
                            if host_forward_id == 1:
                                host_type.append([host, 'GW'])
                                logging.info('Setting device %s as ROUTER',
                                host)
                            else:
                                host_type.append([host, 'OTHER'])
                                logging.info('Setting device %s as OTHER',
                                host)
                    else:
                        host_type.append([host, 'OTHER'])
                        logging.info('Setting device %s as OTHER', host)
                elif sn.walk(dot1d_bridge):
                    host_type.append([host, 'SW'])
                    logging.info('Setting device %s as SwITCH', host)
                else:
                    host_type.append([host, 'OTHER'])
                    logging.info('Setting device %s as OTHER', host)
            except:
                host_type.append([host, 'OTHER'])
                logging.info('Setting device %s as OTHER', host)
        return host_type

    def create_bulk_format(self, host_array, version, **kwarg):
        u"Create bukl format  file to import in NAV"
        community = kwarg['community']
        bulk_format = []
        # The file
        now = datetime.datetime.now()
        now = now.strftime("%Y%m%d%H%M%S")
        folder = '/tmp/nav/'
        if not os.path.exists(folder):
            os.makedirs(folder)
            logging.info('Create folder %s', folder)
        filename = '/tmp/nav/ip_device_bulk_import_' + now + '.txt'
        f = open(filename, 'w+')
        logging.info('Open new file %s', filename)
        for host_line in host_array:
            bulk_format_temp = []
            line = self.my_room + ':'
            bulk_format_temp.append(self.my_room)
            line = line + host_line[0] + ':'
            bulk_format_temp.append(host_line[0])
            line = line + self.my_org + ':'
            bulk_format_temp.append(self.my_org)
            line = line + host_line[1] + ':'
            bulk_format_temp.append(host_line[1])
            if host_line[1] != "SRV":
                line = line + community
                bulk_format_temp.append(community)
            f.write(line + '\n')
            logging.info('Adding line %s in file', line)
            bulk_format.append(bulk_format_temp)
        logging.info('Bulk format %s', bulk_format)
        f.close()
        logging.info('Closing file %s', filename)
        #print "File created in "+filename
        #return bulk_format
        return filename

    def catch_exit(signal, frame):
        u"Exit program on crt+C"
        print
        print 'You pressed Ctrl+C!'
        print 'Exiting...!'
        print
        logging.info('Exiting on Ctrl+C')
        exit(0)

    u"call exit function"
    signal.signal(signal.SIGINT, catch_exit)


###########################################################################
## Class DeviceGrouping
###########################################################################


class DeviceGrouping():
    u"Group device base on ipAddrTable"
    def __init__(self, host_ip, host_array, version, **kwarg):
        self.community = kwarg['community']
        self.host_ip = host_ip
        self.host_array = host_array
        self.version = version
        self.ip_ad_ent_addr = "1.3.6.1.2.1.4.20.1.1"
        sn = nav.Snmp.Snmp(self.host_ip, self.community, self.version)
        logging.info('Create SNMP object for device to group: %s',
        self.host_ip)
        # get current host ipAddrTable
        try:
            host_ip_addr_table = sn.walk(self.ip_ad_ent_addr)
            for host_ip_in_addr_table_tuple in host_ip_addr_table:
                (ip_oid, host_ip_in_addr_table) = host_ip_in_addr_table_tuple
                if host_ip_in_addr_table != self.host_ip:
                    if host_ip_in_addr_table in self.host_array:
                        self.host_array.remove(host_ip_in_addr_table)
                        logging.info('Remove IP %s from devices list',
                        host_ip_in_addr_table)
        except Exception, e:
            print "===== DeviceGrouping error ====="
            print ("%s") % (e)
            logging.error('DeviceGrouping error: %s ', e)

#############################################################################
# Class GetIndirectNextHop
#############################################################################


class GetIndirectNextHop(threading.Thread):
    u"""
    For all ip_route_next_hop, get only those
    which have ip_route_type as indirect.
    """
    def __init__(self, lock, snmp_object, ip, devices,
    version, **kwarg):
        threading.Thread.__init__(self)
        self.community = kwarg['community']
        self.devices = devices
        self.version = version
        self.lock = lock
        self.ip = ip
        self.snmp_object = snmp_object
        self.ip_route_next_hop = "1.3.6.1.2.1.4.21.1.7"
        self.ip_route_type = "1.3.6.1.2.1.4.21.1.8"

    def run(self):
        self.lock.acquire()
        print
        try:
            hop_array = self.snmp_object.jog(self.ip_route_next_hop)
            logging.info('Create SNMP object for IndirectNextHop: %s',
            self.ip_route_next_hop)
            #print hop_array
            for line in hop_array:
                (next_network, router_iP) = line
                #print line
                # remove double base on router_iP
                # remove network 0.0.0.0
                if next_network != '0.0.0.0':
                    # create route type oid
                    network_type = self.snmp_object.get(
                    self.ip_route_type + '.' + next_network)
                    # get only indirect router_iP
                    # 4 mean type is indirect
                    if network_type == 4:
                        #print router_iP
                        # No duplicate IP
                        logging.info('Adding IndirectNextHop: %s', router_iP)
                        if router_iP not in self.devices:
                            self.devices.append(router_iP)
                            # Group routers
                            logging.info('Grouping IndirectNextHop: %s',
                            router_iP)
                            #self.device_grouping(router_iP, devices,
                            #version, community=community)
                            DeviceGrouping(router_iP, self.devices,
                            self.version, community=self.community)
        except Exception, e:
            print
            #print (u"""I'am affraid, looks like something went wrong
            #with %s !""") % (ip)
            print "===== GetIndirectNextHop error ====="
            print ("%s") % (e)
            logging.error('GetIndirectNextHop error: %s', e)
        self.lock.release()

############################################################################
# Class GetLocalNetAddress
############################################################################


class GetLocalNetAddress(threading.Thread):
    u"Get local network devices base on ARP"
    def __init__(self, lock, devices, version, **kwarg):
        threading.Thread.__init__(self)
        self.community = kwarg['community']
        self.devices = devices
        self.version = version
        self.ip_net_to_media_net_address = "1.3.6.1.2.1.4.22.1.3"
        self.lock = lock

    def run(self):
        self.lock.acquire()
        for router in self.devices:
            sn = nav.Snmp.Snmp(router, self.community, self.version)
            logging.info(u"""Create SNMP object for device %s \
            for local network discovery""", router)
            try:
                ip_net_address_array = sn.walk(
                    self.ip_net_to_media_net_address)
                for lines in ip_net_address_array:
                    (ip_net_address_oid, ip_net_address) = lines
                    #print ip_net_address
                    if ip_net_address not in self.devices:
                        logging.info('Add device %s in device list',
                        ip_net_address)
                        self.devices.append(ip_net_address)
                        # Group devices
                        logging.info('Group device %s in device list',
                        ip_net_address)
                        #self.device_grouping(ip_net_address, devices,
                        #version, community=community)
                        DeviceGrouping(ip_net_address, self.devices,
                        self.version, community=self.community)
            except Exception, e:
                print
                print (u"""I'am affraid, looks like something went \
                wrong with %s !""") % (router)
                print "===== GetLocalNetAddress error ====="
                print ("%s") % (e)
                print
                logging.error('GetLocalNetAddress error %s', e)
        self.lock.release()

#############################################################################
# Call main class
#############################################################################
u"call SeedDb class"
if __name__ == '__main__':
    seeddb = SeedDb()
