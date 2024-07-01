import scapy.all as scapy 
import string


# flag 
DEBUG = True

# DEFAULT INPUT 
DEFAULT_IP_ADDRESS="192.168.1.90"
DEFAULT_SUBNET_MASK="255.255.255.0"


# string to array 
def ip_array(ip_addr: str) -> list:
    l = ip_addr.split('.')
    if DEBUG: 
        s = format("Converting Ip address : " + ip_addr + " to array :" + str(l))
        print(s)
    return l

# Array to string
def ip_string(ip_addr_array: list) -> str: 
    s = ".".join(ip_addr_array)
    if DEBUG:    
        print(f"Converting array: {ip_addr_array} to string: {s}")
    return s
    
def __get_net_address(ip_addr: list, subnet_msk: list) -> list: 
    net_addr = list()
    for (ip, sb) in zip(ip_addr, subnet_msk):
        i = int(ip) & int(sb)  
        net_addr.append(str(i))
    return net_addr
    

def getNetAddrs(ip_address: str, subnet_mask: str)-> str: 
    ip_addr_array = ip_array(ip_address)
    subnet_mask_array = ip_array(subnet_mask)
    
    net_address_array =  __get_net_address(ip_addr_array, subnet_mask_array)
    net_address = ip_string(net_address_array)
    return net_address
    

def main(): 
    
    # initialise the variabes regarding the interface and specially its 
    # ip address and address mask
    # get the network address and calculate the number of address that can be scanned for
    network_address =  getNetAddrs(DEFAULT_IP_ADDRESS, DEFAULT_SUBNET_MASK)
    # no_addresses = get_number_available_addresses(network_address)
    
    # active_address_list = scan_all_addresses(network_address, no_addresses)
    
    # print_available_address(active_address_list)
    
    # TO:DO : 
    
    
     
     

if __name__ == "__main__": 
    main()