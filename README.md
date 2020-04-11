
# Blacklist Checker

Description: Verify if an IP is on a blacklist (DNSBL)  
File name: blcheck.py  
Version: 1.0.1  
Status: Production  
Python version: 3  
Requirements: python3-dnspython  
Author: y-n0t  
License: GPL  

## What does it do?

This script will do a basic check the validate the provided argument, and if it is, query the IP on different DNSBL and return the status.  

## What is a DNSBL?

Here is a good summary from Wikipedia:  
~~~
A Domain Name System-based Blackhole List (DNSBL) or Real-time Blackhole List (RBL) is an effort to stop email spamming.
It is a "blacklist" of locations on the Internet reputed to send email spam.
The locations consist of IP addresses which are most often used to publish the addresses of computers or networks linked to spamming;
most mail server software can be configured to reject or flag messages which have been sent from a site listed on one or more such lists.
The term "Blackhole List" is sometimes interchanged with the term "blacklist" and "blocklist".

A DNSBL is a software mechanism, rather than a specific list or policy. There are dozens of DNSBLs in existence,[1] which use a wide array of
criteria for the listing and delisting of addresses. These may include listing the addresses of zombie computers or other machines being
used to send spam, Internet service providers (ISPs) who willingly host spammers, or those which have sent spam to a honeypot system. 
~~~

## How to use it?

Here some examples :  
* python blcheck.py mail.example.com
* python blcheck.py 8.8.8.8

## Settings

You can change the list of DNSBLs  in the section named "dnsblList".  
There is also a section where you can adjust the DNS resolver : "# Settings for the dns.resolver module".  

## To do:

* Add an option that explain the return status, eg. 127.0.1.4 = phish domain.
* Add a new section to search URI DNSBLs.
