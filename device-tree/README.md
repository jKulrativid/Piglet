# Device Tree (DT) and DT Overlay Generator

## References
https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18842279/Build+Device+Tree+Blob#BuildDeviceTreeBlob-GenerateDTSFilesUsingXSCT

## Prerequisite
- Vitis
- dtc (device tree comipler) command
- Hardware Description File (.xsa)

## Steps
1. source Vitis settings64.sh file to ensure that 'xcst' is available
2. git clone https://github.com/Xilinx/device-tree-xlnx and chechout to tag <xilinx_v20XX.X>,
for example, if the using Vitis version is 2023.2, then uses the tag "xilinx_v2023.2".
3. source gen-dt.sh file
