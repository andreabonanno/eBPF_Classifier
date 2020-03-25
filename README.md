# eBPFtest

Tested on Ubuntu 19.10, Kernel 5.3.0

Prerequisiti:

- iovisor bcc library (bynary installer)
https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

CLI arguments:

- -l, --learn           
Creates databses of normal behaviour for the items the
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


TODO:
- Ultimare l'implementazione dell'algoritmo di riconoscimento delle anomalie (a partire da un log di syscall oppure in maniera dinamica) secondo quanto visto in https://ieeexplore.ieee.org/document/7414047
