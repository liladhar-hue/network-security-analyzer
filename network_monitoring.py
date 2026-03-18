import socket
import psutil

def get_active_interface():
    interfaces = psutil.net_if_addrs() # getting all inetrfaces in one dic.

    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            #check for IPv4(using AF_INET for ipV4)
            if address.family == socket.AF_INET:
               if not address.address.startswith("127.0.0.1"):   #ignore localhost
                   return interface_name, address.address
    return None, None


if __name__ == "__main__":
    interface, ip = get_active_interface()

    if interface:
       print(f"[+] Active interface : {interface} ")
       print(f"[+] ip address: {ip} ") 
    else :
         print("No service found " )

