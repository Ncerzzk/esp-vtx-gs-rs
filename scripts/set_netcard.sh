
dev_name=$1

nmcli device set $dev_name managed no
ifconfig $dev_name down
iw dev $dev_name set monitor otherbss
ifconfig $dev_name up
iw dev $dev_name set channel 11

