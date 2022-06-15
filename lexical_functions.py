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

#### LEXICAL FEATURES #####################################

# LENGTH FEATURES -------------------------------------------

#Longitud URL completa
def len_url (url):
    return len(str(url))

#Longitud hostname 
def len_hostname (hostname):
    return len(str(hostname))

#Longitud path 
def len_path (path):
    return len(str(path))

#Longitud param 
def len_param (param):
    return len(str(param))

#Longitud token más largo en el host
def long_token_host(host):
    host_str=str(host)
    tokens_host=host_str.split('.')
    long_token=max(tokens_host,key=len)
    return len(long_token)


def long_token_path(path):
        
    tokens_path=path.split('/')
    long_token=max(tokens_path,key=len)
    return len(long_token)


def long_token_param(param):
    
    tokens_param=param.split('?')
    long_token=max(tokens_param,key=len)
    return len(long_token)

def Long_token_URL(hostname, path,param):
    
    max_token_host=long_token_host(hostname)
    max_token_path=long_token_path(path)
    max_token_param=long_token_param(param)

    longest_token=max([max_token_host,max_token_path,max_token_param])
    return longest_token

def hostPathRatio(hostname,path):

    long_host=len_hostname(hostname)
    long_path=len_path(path)

    return long_host/long_path


def hostParamRatio(hostname,param):

    long_param=len_param(param)
    
    if long_param==0:
        return 0

    else:
        long_hostname=len_hostname(hostname)
        long_param=len_param(param)

        return long_hostname/long_param
   
    

def hostUrlRatio(hostname,url):

    long_host=len_hostname(hostname)
    long_url=len_url(url)

    return long_host/long_url

#Hay que pasar URL completa (hostname+path)
def pathUrlRatio(url,path):

    long_url_=len_url(url)
    long_path_=len_path(path)
    return long_path_/long_url_


#Hay que pasar URL completa (hostname+path)
def paramUrlRatio(url,param):

    long_param=len_param(param)
    
    if long_param==0:
        return 0

    else:
        long_url=len_hostname(url)
        long_param=len_param(param)

        return long_param/long_url
  


# COUNTING FEATURES ------------------------------------

#Pasar URL+hostname
def count_special_char(url):

    ocurrences=url.count('-')
    #print("ocurrentes - :"+str(ocurrences))
    ocurrences+=url.count('@')
    #print("ocurrentes @ :"+str(ocurrences))
    ocurrences+=url.count('?')
    #print("ocurrentes ? :"+str(ocurrences))
    ocurrences+=url.count('.')
    #print("ocurrentes . :"+str(ocurrences))
    ocurrences+=url.count('%')
    #print("ocurrentes % :"+str(ocurrences))
    ocurrences+=url.count('http')
    #print("ocurrentes http :"+str(ocurrences))
    ocurrences+=url.count('www')
    #print("ocurrentes www :"+str(ocurrences))

    return ocurrences

#Pasar URL+hostname
def count_digits(url):
    digit=0
    for character in url:
        if character.isdigit():
            digit+=1
  
    return digit

def count_letter(url):
    letter=0
    for character in url:
        if character.isalpha():
            letter+=1
   
    return letter

def count_token(hostname,path,param):
    
    tokens_hostname=len(hostname.split('.'))
    tokens_path=len(path.split('/'))
    tokens_param=len(param.split('?'))

    return tokens_hostname,tokens_path,tokens_param

def count_nonalpha(url):
    nonalpha=0
    for character in url:
        if character.isalnum()==False:
            nonalpha=nonalpha+1
   
    return nonalpha

def count_periodt(url):
    periodt=0
    for character in url:
        if character=='.':
            periodt+=1
   
    return periodt


#PATTERN FEATURES ----------------------------------------

#Calculate each one for : hostname, path and whole url
def case_changes(url):
   
    cadena=""
    ocurrencias=0

    #Cadena solo con letras
    for character in url:
        if character.isalpha():
           cadena+=character

    #Calcular ocurrencias cambio de mayuscula a minuscula      
    for i in range(len(cadena)-1):
        if cadena[i].islower()!=cadena[i+1].islower():
            ocurrencias=ocurrencias+1

    return ocurrencias

def pattern_char(url):

    
    l=len(url)

    if l>0:
        count=0
        res=url[0]
        #print(res)

        for i in range(l):
            cur_count=1
            for j in range (i+1,l):
                if(url[i]!=url[j]):
                    break
                cur_count +=1

            if cur_count>count:
                count=cur_count
                res=url[i]

        return count
    else:
        return 0


#BINARY FEATURES ----------------------------------------

#¿Aparece tld fuera de sitio?
def tld(hostname,url):

    tokens_host=hostname.split('.')
    top_level_domain=tokens_host[-1] #Coger ultimo elemento

    ocurrences=url.count(top_level_domain)

    if ocurrences >1 :
        return True
    else:
        return False

def out_ip_host(hostname):

    return(iptools.ipv4.validate_ip(hostname))

#Comparar dominio con los top 1 million domains
#Si en el hostname aparece alguno de los dominios mas recurrentes

def cisco_in_hostname(hostname,domain_list):

   #Comparar si el hostname coincide con alguno de los top
   #return(any(hostname in domain for domain in domain_list)) 

   return(any(domain in hostname for domain in domain_list))

#Domain recurrentes fuera de lugar (en path)
def cisco_out_url(path_param,domain_list):

   return(any(domain in path_param for domain in domain_list)) 

#Pasar url completa
def key_client(url):

    ocurrences=url.count("client")

    if ocurrences >1 :
        return True
    else:
        return False

def key_admin(url):

    ocurrences=url.count("admin")

    if ocurrences >1 :
        return True
    else:
        return False

def key_server(url):

    ocurrences=url.count("server")

    if ocurrences >1 :
        return True
    else:
        return False


def key_login(url):

    ocurrences=url.count("login")

    if ocurrences >1 :
        return True
    else:
        return False


# RATIO FEATURES ----------------------------------

def vowel_consonant(url):
    consonant=0
    vowel=0

    for character in url:
        if character.isalpha():
      
            if character != 'a' and character != 'e' and character != 'i' and character != 'o' and character != 'u' :
                #print("consonante :"+character)
                consonant=consonant+1
            else:
                #print("vocal :"+character)
                vowel=vowel+1
    return (vowel/consonant)

def digit_letter(url):

    digit=count_digits(url)
    letter=count_letter(url)

    if digit==0 | letter==0:
        return 0
    else:   
        return (digit/letter)

def avg_tokens(hostname,path,param):
    
    tokens_hostname=hostname.split('.')
    mean_hostname= sum(map(len,tokens_hostname))/float(len(tokens_hostname))
    #print(mean_hostname)

    tokens_path=path.split('/')
    if len(tokens_path)==1 and tokens_path[0]=='':
        mean_path=0
    else:
        mean_path= sum(map(len,tokens_path[1:]))/float(len(tokens_path))
    #print(mean_path)

    tokens_param=param.split('?')
    if  len(tokens_param)==1 and tokens_param[0]=='':
        mean_param=0
    else:
        mean_param= sum(map(len,tokens_param[1:]))/float(len(tokens_param))
    #print(mean_param)

    num_total_tokens=len(tokens_hostname)+len(tokens_path)+len(tokens_param)
    mean_tokens=(mean_hostname+mean_path+mean_param)/num_total_tokens
    return ((mean_tokens))
    
#Media de continuidad de caracteres
def continuity_rate(url):
    count=0
    different_char=0

    current_char=url[0]

    for i in range(len(url)-1):

        if url[i]==url[i+1]:
            #print(url[i])
            count+=1
            if url[i]!=current_char:
                different_char+=1
                current_char=url[i]

    #print(count)
    #print(different_char)    
    return (count/different_char)