# eBPFtest

Tested on Ubuntu 19.10, Kernel 5.3.0

Goal:
Tool for learning the normal behaviour of a task or a container and store it as a file.
The same tool can then monitor a process or container for which the normal behaviour has been learned, and look for anomalies at run-time.

Prerequisites:

- iovisor bcc library (bynary installer)
https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

CLI arguments:

<pre>sudo python Classifier_test.py --help
Usage: Classifier_test.py [options]

Options:
  -h, --help            show this help message and exit
  -l, --learn           Creates databses of normal behaviour for the entity the
                        program listened to.
  -m, --monitor         Monitor the selected process/container for anomalies
                        using a previosly generated normal behaviour database.
  -t TASK_ID, --task=TASK_ID
                        Start the program in task mode. Needs the name of the executable to
                        track as argument (filename without the path).
  -c CONTAINER_ID, --container=CONTAINER_ID
                        Start the program in container mode. Needs the
                        container id to track as argument.
  -v, --verbose         Start the program in verbose mode, printing more info.
</pre>

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
Stop monitoring with SIGINT Ctrl-C
