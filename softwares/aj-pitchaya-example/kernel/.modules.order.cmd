cmd_/home/ubuntu/stream/kernel/modules.order := {   echo /home/ubuntu/stream/kernel/dma-proxy.ko; :; } | awk '!x[$$0]++' - > /home/ubuntu/stream/kernel/modules.order
