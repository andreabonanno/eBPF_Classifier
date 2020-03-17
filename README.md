# eBPFtest

Tested on Ubuntu 19.10, Kernel 5.3.0

Prerequisiti:

- iovisor bcc library (bynary installer)
https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary

CLI arguments:

- -t crea o sovrascrive "tracefile.txt", attuale log delle syscall eseguite dai containers.
- -c procede alla creazione e classificazione delle syscall bags creando un database per ogni container scoperto.

TODO:
- Avendo creato i database delle "bags" di syscall, ultimare l'implementazione dell'algoritmo di riconoscimento delle anomalie (a partire da un log di syscall oppure in maniera dinamica) secondo quanto visto in https://ieeexplore.ieee.org/document/7414047
