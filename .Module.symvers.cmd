cmd_/home/xt/netfilter_hook/Module.symvers := sed 's/ko$$/o/' /home/xt/netfilter_hook/modules.order | scripts/mod/modpost  -a   -o /home/xt/netfilter_hook/Module.symvers -e -i Module.symvers   -T -
