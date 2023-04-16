sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 10.0.2.50/24 dev veth0
sudo ip link set veth0 up
sudo ip link set veth1 up
