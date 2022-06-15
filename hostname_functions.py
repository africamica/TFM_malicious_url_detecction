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
# HOST BASED FEATURES ###########################################

#Numero de subdominios
def number_of_subdomains(ip,shodan_host):
#def number_of_subdomains(shodan_host):
    try:
        whois_dict=whois(ip)
        whois_dict=whois_dict
    except:
        whois_dict={}

    ln1=whois_dict.get('nets',None)   
    ln2=shodan_host.get('domains',None)

    ln= ln1 or ln2
    return( len(ln) if ln else None)
    
    
    #obj=IPWhois(ip)
    #res=obj.lookup_whois() #Si imprimes esta objeto obtienes parametros
    
    #ln1=res['nets']
    #ln2=shodan_host.get('domains',None)

    #ln= ln1 or ln2
    #return( len(ln) if ln else None)

#Registration date
def registration_date(hostname):

    try:
        query=whois.query(hostname)
        return (query.creation_date)
    except:
        return(None)

#Expiration date
def expiration_date(hostname):

    try:
        query=whois.query(hostname)
        return (query.expiration_date)
    except:
        return(None)


#Age (return days)
def age_host(hostname):

    try:
        query=whois.query(hostname)
        age= datetime.now() - query.creation_date
        return(age.days)
    except:
        return(None)


#(return days)
def intented_life_span(hostname):

    try:
        query=whois.query(hostname)
        subtract=query.expiration_date - query.creation_date
        return(subtract.days)
    except:
        return(None)
       

def life_remaining(hostname):

    try:
        query=whois.query(hostname)
        remain=query.expiration_date - datetime.now()
        return(remain.days)
    except:
        return(None)
 

def registrar(hostname):


    try:
        query=whois.query(hostname)
        return(query.registrar)
    except:
        return(None)

    
def registration_country(hostname):

    try:
        query=whois.query(hostname)
        return(query.registrant_country)
    except:
        return("Unknown")
 
  
def hosting_country(shodan_host):  
 
    host_country=shodan_host.get('country_name',"Unknown")
    return(host_country)

def num_open_ports(shodan_host):

    ports=shodan_host.get('ports','')
    lp=len(ports) if ports else 0
    return lp


#Pasar url completa : service+://+hostname+url!
def is_live(url):

    try:
        is_live_cal=get(url).status_code==200
        return is_live_cal
    except:
        return False

def isp(shodan_host):

    isp_host=shodan_host.get('isp','Unknown')
    return isp_host
#Pasar url completa : service+://+hostname+url!
#Devuelve en segundos
def connection_speed(url):

    if is_live(url):
        return get(url).elapsed.total_seconds()
    else:
        return None

def ttl_from_registration(url,hostname):

    earliest_date_seen=first_seen(url)
    reg_day=registration_date(hostname)
    try:
        ttl_from_reg=earliest_date_seen-reg_day
        return ttl_from_reg.days
    except:
        return 0



def first_seen(snapshots):

    try:
        fs=snapshots[0]
        return(fs)
    except:
        return(datetime.now())


def last_seen(snapshots):

    try:
        fs=snapshots[-1]
        return(fs)
    except:
        return(datetime.now())

def days_since_last_seen(snapshots):
    last=last_seen(snapshots)
    dsls=datetime.now()-last
    return dsls.days

def days_since_first_seen(snapshots):
    first=first_seen(snapshots)
    dsfs=datetime.now()-first
    return dsfs.days

#Pasar url completa : service+://+hostname+url!
def number_of_updates(snapshots):
    return(len(snapshots))

def updated_date(hostname):

    try:
         query=whois.query(hostname)
         return(query.last_updated)
    except:
        return None

def days_since_update_date(hostname):
  
    update_date=updated_date(hostname)
    if update_date==None:
        return 0
    else:
        days_since=datetime.now()-update_date
        return days_since.days

def average_update_frequency(snapshots):
    diffs=[(t-s).days for s,t in zip(snapshots,snapshots[1:])]
    l=len(diffs)
    if l>0:
        return sum(diffs)/l
    else:
        return 0