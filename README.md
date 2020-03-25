# eBPFtest

Tested on Ubuntu 19.10, Kernel 5.3.0

Prerequisiti:

- iovisor bcc library (bynary installer)
https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

CLI arguments:

- -l, --learn           
Creates databases of normal behaviour for the items the
                        program listened to
-   -m, --monitor         
Monitor the selected process/container for anomalies
                        using a previosly generated normal behaviour database
- -t TASK_ID, --task=TASK_ID 
Start the program in task mode. Needs the taskname to
                        track as argument.
- -c CONTAINER_ID, --container=CONTAINER_ID
Start the program in container mode. Needs the
                        container id to track as argument.
-  -v, --verbose         
Start the program in verbose mode, printing more info

Example:

Learn:
<pre>sudo python Classifier_test.py -c 6b17fbeeefef -lv
</pre>
Stop learning with SIGINT Ctrl-C
<pre>Syscall bags and count for 6b17fbeeefef (NORMAL BEHAVIOUR)
[&apos;exit&apos;, &apos;mmap&apos;, &apos;mprotect&apos;, &apos;clone&apos;, &apos;newstat&apos;, &apos;newfstat&apos;, &apos;close&apos;, &apos;access&apos;, &apos;prctl&apos;, &apos;getdents&apos;, &apos;openat&apos;]
(13, 0, 0, 0, 0, 40, 103, 0, 1, 40, 91, 3) , 1
(5, 29, 28, 33, 155, 54, 103, 0, 25, 38, 109, 9) , 1
(0, 0, 0, 0, 0, 38, 89, 0, 0, 36, 89, 0) , 3
(0, 0, 0, 0, 0, 40, 91, 0, 0, 40, 91, 0) , 18
(0, 0, 0, 0, 125, 37, 87, 0, 0, 34, 88, 1) , 1
(0, 0, 0, 0, 0, 36, 86, 0, 0, 32, 86, 1) , 1
(22, 236, 194, 48, 275, 180, 278, 116, 28, 60, 247, 64) , 1
</pre>
Monitor:
<pre>sudo python Classifier_test.py -c 6b17fbeeefef -mv</pre>
Then start the container:
<pre>sudo docker start 6b17fbeeefef</pre>
Stop monitoring with SIGINT Ctrl-C:
<pre>MISMATCH 6


Syscall bags and count for 6b17fbeeefef (NORMAL BEHAVIOUR)
[&apos;exit&apos;, &apos;mmap&apos;, &apos;mprotect&apos;, &apos;clone&apos;, &apos;newstat&apos;, &apos;newfstat&apos;, &apos;close&apos;, &apos;access&apos;, &apos;prctl&apos;, &apos;getdents&apos;, &apos;openat&apos;]
(5, 29, 28, 33, 155, 54, 103, 0, 25, 38, 109, 9) , 1
(0, 0, 0, 0, 0, 38, 89, 0, 0, 36, 89, 0) , 3
(0, 0, 0, 0, 0, 40, 91, 0, 0, 40, 91, 0) , 18
(0, 0, 0, 0, 125, 37, 87, 0, 0, 34, 88, 1) , 1
(0, 0, 0, 0, 0, 36, 86, 0, 0, 32, 86, 1) , 1
(22, 236, 194, 48, 275, 180, 278, 116, 28, 60, 247, 64) , 1
(13, 0, 0, 0, 0, 40, 103, 0, 1, 40, 91, 3) , 1


Syscall bags and count for 6b17fbeeefef (MONITORED BEHAVIOUR)
[&apos;exit&apos;, &apos;mmap&apos;, &apos;mprotect&apos;, &apos;clone&apos;, &apos;newstat&apos;, &apos;newfstat&apos;, &apos;close&apos;, &apos;access&apos;, &apos;prctl&apos;, &apos;getdents&apos;, &apos;openat&apos;]
(5, 29, 28, 33, 156, 56, 110, 0, 25, 38, 116, 9) , 1
(0, 0, 0, 0, 0, 36, 87, 0, 0, 32, 87, 0) , 1
(22, 289, 194, 49, 277, 207, 310, 138, 28, 60, 279, 68) , 1
(0, 0, 0, 0, 0, 38, 89, 0, 0, 36, 89, 0) , 3
(0, 0, 0, 0, 0, 40, 91, 0, 0, 40, 91, 0) , 11
(0, 0, 0, 0, 0, 36, 86, 0, 0, 32, 86, 1) , 1
</pre>
TODO:
- Stabilire le metriche in base alle quali i mismatch nei dizionari di comportamento "normale" e comportamento monitorato sono considerati un'anomalia, secondo quanto visto in https://ieeexplore.ieee.org/document/7414047
- Implementare la modalita' di segnalazione anomalie in real-time