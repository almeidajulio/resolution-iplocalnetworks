#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
/*******************************************************************************
  Copyright (C) 2021, Almeida, Julio.

  Filename: main.py
  Project: Pre processamento Nessus
  Description: Pre processamento de reports Nessus para VPN DHCP random IP


  Date           Version      Action          Author             Changes
  ------------------------------------------------------------------------------
  2021/04/27      1.0          Init            Julio C. Almeida   N/A
*******************************************************************************/

"""
import os
import csv
import logging
import argparse

from random import getrandbits
from ipaddress import IPv4Network, IPv4Address

# TODO: import xml element tree to parser file
import xml.etree.ElementTree as ET


# TODO: Classe para fazer o parser geral
class CustomFormatter(argparse.RawDescriptionHelpFormatter,
                      argparse.ArgumentDefaultsHelpFormatter):
    pass


class Finder():
    def __init__(self):
        pass

    def methodnext(self, dict, filter, search):
        res = False
        try:
            for sub in dict:
                if sub[filter] == search.lower():
                    res = sub
                    break
        except:
            return res

        return res


class Nessus():
    def __init__(self, file, dest):
        self.iplist = []
        self.file = file
        self.dest = dest
        self.finder = Finder()

    # TODO: função para randomizar um IP dentro de um scopo de rede
    def randomIP(self):
        addr = None
        # network containing all addresses from
        subnet = IPv4Network("192.168.252.0/22")

        # subnet.max_prefixlen contains 32 for IPv4 subnets and 128 for IPv6 subnets
        # subnet.prefixlen is 24 in this case, so we'll generate only 8 random bits
        bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen)

        # to get an IP address from the previously specified subnet
        while True:
            addr = IPv4Address(subnet.network_address + bits)
            if addr not in self.iplist:
                break

        addr_str = str(addr)

        return addr_str

    # TODO: função para verificar classe (public, private, invalid)
    def checkIpAddress(self, ip):
        try:
            addr = IPv4Address(ip)

            if addr.is_private:
                response = "private"

            if addr.is_global:
                response = "global"

        except Exception:
            response = "invalid"

        return response

    # TODO: função para fazer a correlação entre nome,hostname,netbios e ip
    def findCSV(self, name, hostname, biosname):
        try:
            reader = csv.DictReader(open('.\src\hostnames\hostname.csv', 'r'))
            self.dict_list = []
            for line in reader:
                self.dict_list.append(line)
                if line['ip'] not in self.iplist:
                    self.iplist.append(line['ip'])

            if hostname:
                srch = hostname
                tp = "hostname"
            elif biosname:
                srch = biosname
                tp = "biosname"
            else:
                srch = name
                tp = "name"

            result = self.finder.methodnext(
                self.dict_list,
                tp,
                srch
            )
            return result

        except:
            return

    # TODO: função para efetuar nos dados .nessus troca de IPs
    def parser(self):
        hosts = []
        tree = ET.parse(self.file)

        for host in tree.findall('Report/ReportHost'):
            try:
                ipaddrObj = host.find("HostProperties/tag/[@name='host-ip']")
                old_ipaddr = ipaddrObj.text
            except Exception as e:
                logging.error("[ERROR] Filed: {1} - {0}".format(e, "host-ip"))
         
            try:
                name = host.attrib['name']
                name = name.lower()
            except Exception as e:
                logging.error("[ERROR] Filed: {1} - {0}".format(e, "name"))
                name = None

            try:
                hostname = host.find(
                    "HostProperties/tag/[@name='hostname']").text
                hostname = hostname.lower()
            except Exception as e:
                logging.error("[ERROR] Filed: {1} - {0}".format(e, "hostname"))
                hostname = None

            # try:
            #     domain = host.find(
            #         "HostProperties/tag/[@name='wmi-domain']").text
            # except Exception as e:
            #     logging.error("[ERROR] {} \n {}".format(e, host))
            #     domain = None

            try:
                netbions_name = host.find(
                    "HostProperties/tag/[@name='netbios-name']").text
                netbions_name = netbions_name.lower()
            except Exception as e:
                logging.error("[ERROR] Filed: {1} - {0}".format(e, "netbios-name"))
                netbions_name = None

            # try:
            #     macaddr = host.find(
            #         "HostProperties/tag/[@name='mac-address']").text.split("\n")
            # except Exception as e:
            #     logging.error("[ERROR] {} \n {}".format(e, host))
            #     macaddr = []

            # try:
            #     os = host.find(
            #         "HostProperties/tag/[@name='operating-system']").text
            # except Exception as e:
            #     logging.error("[ERROR] {} \n {}".format(e, host))
            #     os = None

            search_csv = self.findCSV(name, hostname, netbions_name)
            if not search_csv:
                dict_hosts = {}
                dict_hosts['name'] = name
                dict_hosts['hostname'] = hostname
                dict_hosts['ip'] = self.randomIP()
                dict_hosts['biosname'] = netbions_name

                hosts.append(dict_hosts)

                ipaddrObj.text = self.randomIP()
                new_ipaddr = host.find(
                    "HostProperties/tag/[@name='host-ip']").text

                with open('.\src\hostnames\hostname.csv', 'a', newline='') as csvfile:
                    fieldnames = ['name', 'hostname', 'ip', 'biosname']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    if csvfile.tell() == 0:
                        writer.writeheader()
                    writer.writerows([dict_hosts])

            else:
                ipaddrObj.text = search_csv['ip']
                new_ipaddr = host.find(
                    "HostProperties/tag/[@name='host-ip']").text

            logging.debug({
                "name": name,
                "hostname": hostname,
                "netbios-name": netbions_name,
                "old_ipaddr": old_ipaddr,
                "new_ipaddr": new_ipaddr
            })

            tree.write(self.dest, encoding='utf-8', xml_declaration=True)


def engines(args):
    nesses_c = Nessus
    src = args.src
    files_src = [(f) for f in os.listdir(src) if f.endswith(".nessus")]
    dst = args.dst

    logging.info("[INFO] Starting parsing {} file(s)".format(len(files_src)))

    for file in files_src:
        logging.info("[INFO] Parsing File {}".format(file))
        dest = "{}{}".format(dst, file)
        file = "{}{}".format(src, file)
        result = nesses_c(file, dest).parser()


def main():
    parser = argparse.ArgumentParser(
        prog='Parser Nessus',
        description='Módulo para mudar dados de arquivos .nessus',
        formatter_class=CustomFormatter,
        add_help=False
    )
    parser.add_argument('-h', '--help', action='help',
                        default=argparse.SUPPRESS,
                        help='show this help message and exit')
    parser.add_argument('-d', '--debug', action='store_true',
                        default=False,
                        help='logar todas as atividades, DEBUG mode')
    parser.add_argument('--version', action="version",
                        version="version is\n  0.0.1")

    subparsers = parser.add_subparsers()

    """
    Definição dos parametros para uso do parser Nessus
    """
    PS = subparsers.add_parser(
        'parser-nessus', help='ajustar arquivos com network local via netbios ou hostname')
    PS.add_argument(
        '-src', action="store", default=".\\data\\",
        dest='src', help='informe a pasta origem dos arquivos .nessus'
    )
    PS.add_argument(
        '-dst', action="store", default=".\\data_changed\\",
        dest='dst', help='informe a pasta destino dos arquivos modificados'
    )
    PS.set_defaults(func=engines)

    # CommandLine Capture params:
    try:
        args = parser.parse_args()
        debugMode(args.debug)
        args.func(args)
    except Exception as e:
        parser.print_help()
        logging.error("[ERROR] ".format(e))


def debugMode(debug):
    # logging setup and parametrizes script DEV OR PROD
    if debug:
        level = logging.DEBUG
    else:
        level = logging.WARNING

    log_format = "%(asctime)s::%(levelname)s::%(name)s::"\
        "%(filename)s::%(lineno)d::%(message)s"
    logging.basicConfig(
        filename='./src/logging/logging.log',
        format=log_format,
        level=level
    )
    logging.info('[INFO] Running Application')
    logging.getLogger('app')


if __name__ == "__main__":
    # TODO: Change path location
    current = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
    os.chdir(r'%s' % os.path.normcase(current))

    # TODO: start program modify .nessus
    main()
