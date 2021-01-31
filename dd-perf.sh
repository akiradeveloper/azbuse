CNT=1000
dd if=$1 of=/dev/null bs=4k count=$CNT iflag=direct
dd if=$1 of=/dev/null bs=16k count=$CNT iflag=direct
dd if=$1 of=/dev/null bs=64k count=$CNT iflag=direct
dd if=$1 of=/dev/null bs=256k count=$CNT iflag=direct
dd if=$1 of=/dev/null bs=1m count=$CNT iflag=direct