cmd_/home/ubuntu/stream/kernel/Module.symvers := sed 's/\.ko$$/\.o/' /home/ubuntu/stream/kernel/modules.order | scripts/mod/modpost -m -a  -o /home/ubuntu/stream/kernel/Module.symvers -e -i Module.symvers   -T -