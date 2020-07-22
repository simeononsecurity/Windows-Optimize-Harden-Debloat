w32tm /config /manualpeerlist:"192.168.1.1 0.us.pool.ntp.org 1.us.pool.ntp.org 2.us.pool.ntp.org 3.us.pool.ntp.org" /syncfromflags:manual /reliable:YES /update
net stop w32time
net start w32time
w32tm /resync
w32tm /query /peers