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
<pre>Normal behaviour data has been gathered for 6b17fbeeefef after 4 epochs (4000 syscalls)
Cosine similarity progression for 6b17fbeeefef:
[0.4422768165245944, 0.23452674820108954, 0.3922994075400175, 0.9983715142893775]
</pre>
Monitor:
<pre>sudo python Classifier_test.py -c 6b17fbeeefef -mv</pre>
Then start the container:
<pre>sudo docker start 6b17fbeeefef</pre>
Stop monitoring with SIGINT Ctrl-C or when anomaly is found

TODO:
- Stabilire le metriche in base alle quali i mismatch nei dizionari di comportamento "normale" e comportamento monitorato sono considerati un'anomalia, secondo quanto visto in https://ieeexplore.ieee.org/document/7414047
- Implementare la modalita' di segnalazione anomalie in real-time