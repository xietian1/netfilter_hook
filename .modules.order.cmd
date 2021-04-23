cmd_/home/xt/netfilter_hook/modules.order := {   echo /home/xt/netfilter_hook/mydrv.ko; :; } | awk '!x[$$0]++' - > /home/xt/netfilter_hook/modules.order
