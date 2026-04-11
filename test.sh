#!/bin/sh

# load firewall module
insmod firewallExtension.ko || { echo "Cannot insert firewallExtension module" ; exit 1; }

./Setup/firewallSetup W Setup/rules.txt
wget -O /dev/null -t 2 http://www.google.co.uk/ || { echo "Wget test failed"; rmmod firewallExtension; exit 1 ;} 
echo "Wget test passed"
curl -o /dev/null http://www.google.co.uk/ && { echo "Curl test failed"; rmmod firewallExtension; exit 1 ;}
echo "Curl test passed"
curl -o /dev/null https://www.google.co.uk/ || { echo "Curl ssl test failed"; rmmod firewallExtension; exit 1 ;}
echo "Curl ssl test passed"
rmmod firewallExtension || { echo "cannot remove firewall Extension module"; exit 1 ;}
echo "OK"
exit 0
