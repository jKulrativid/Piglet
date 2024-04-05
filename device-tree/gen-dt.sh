#!/bin/bash
xsct <<EOF
hsi open_hw_design /home/jkulrativid/piglet_kr26.xsa
hsi set_repo_path /home/jkulrativid/device-tree-xlnx
hsi create_sw_design device-tree -os device_tree -proc psu_cortexa53_0
hsi set_property CONFIG.dt_overlay true [hsi::get_os]
hsi generate_target -dir piglet_kr26
hsi close_hw_design staging_wrapper
exit
EOF

cd piglet_kr26
dtc -@ -O dtb -o pl.dtbo pl.dtsi
cd ../
cp piglet-kr26/pl.dtbo piglet_kr26.dtbo
