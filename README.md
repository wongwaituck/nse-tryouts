# nse-tryouts
My attempt at writing nmap scripts. The vulnerable program has a buffer overflow vulnerability, and the script detects it and is able to exploit it, with a prepared payload.

## DEMO  (Click to view video)
<a href="http://www.youtube.com/watch?feature=player_embedded&v=SLjzacHK7V8
" target="_blank"><img src="http://img.youtube.com/vi/SLjzacHK7V8/2.jpg" 
alt="Demo Video for Nmap Script" width="240" height="180" border="10" /></a>

## vuln service setup
Compile vuln with the following command:

`gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie`

Copy vuln and wrapper.py in `oh_so_exploitable` to the same folder  on an x86 Ubuntu machine, disable ASLR.

`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

Run the wrapper script to start the vulnerable service

`./wrapper.py`

Note that this was tested on Ubuntu 16.04.2

## nmap script setup
Copy `waituck-vuln.nse` to `/usr/share/nmap/scripts` and `evil-waituck` (the payload) to `/usr/share/nmap/nselib/data`

Run the following command on nmap on the target host

`nmap --script waituck-vuln -p 4444 <host>`

## Credits
The following were the references used for this:

[1] https://svn.nmap.org/nmap/scripts/ftp-vsftpd-backdoor.nse

[2] Pale, P. C. (2015). Mastering Nmap Scripting Engine. Birmingham, UK: Packt Publishing - ebooks Account.

## TODO
Figure out why hosting it with ncat fails
