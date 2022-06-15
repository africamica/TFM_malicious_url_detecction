
from ctypes import sizeof
import json, tempfile
import whois
import zipfile
import io
import csv
import sys, argparse, pprint
import iptools
from socket import gethostbyname
from operator import truediv
from pathlib import Path
from statistics import mean
from webbrowser import get
from datetime import datetime
from shodan import Shodan
from socket import gethostbyname
from requests import get
from urllib.parse import urlparse
from re import compile
from json import dump, loads
from time import sleep
from shodan import Shodan
from ipwhois import IPWhois
from waybackpy import cdx_snapshot
from waybackpy import WaybackMachineCDXServerAPI
import ipwhois

#FUNCIONES CALCULO PARAMETROS ----------------------------------------

#USEFULL FUNCTIONS    ######################################
def shodan_get_host(ShodanApi,ip):
    try:

        shodan_host=ShodanApi.host(ip)
        return shodan_host
    except:
        return {}
        
def valid_tld(tld,tld_list):
    return(any(valid_tld in tld for valid_tld in tld_list))

def obtain_tld(hostname) :
    tokens_host=hostname.split('.')
    top_level_domain=tokens_host[-1] #Coger ultimo elemento
    return top_level_domain

#Obtener url completa
def whole_url(service,hostname,url):
    service_lowecase=service.lower()
    whole_url=service_lowecase+"://"+hostname+url
    return(whole_url)

#Separar entre path y param
def split_path_param(url):
    separate=url.split('?')
    path=separate[0]
    param=url.replace(path,"")

    return path,param

#Obtener snapshots
def get_snapshots(url):
    cdx=WaybackMachineCDXServerAPI(url)
    snapshots=cdx.snapshots()
    list_snapshots=[]

    try:
        for snapshot in snapshots:
            timestamp_snap=snapshot.datetime_timestamp
            list_snapshots.append(timestamp_snap)

        return list_snapshots
    except:

        list_snapshots=[]
        return list_snapshots