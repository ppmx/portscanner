# Experimental Port Scanner

Performs a SYN san on a specific host and port.

```
$ make
mkdir -p build/
clang -Wall -Wextra ./src/syn_scanner.c -o ./build/syn_scanner
$ sudo ./build/syn_scanner wlp4s0 192.168.0.1 80
open
$ sudo ./build/syn_scanner wlp4s0 192.168.0.1 1234
closed
```

