# Python program to detect vulnerability with CVE-2022-32073 in large networks

This python program runs nmap on an address passed as an argument, by default it runs on all ports but port number can also be given as an argument. It runs nmap with custom created **wolf_ssh_version.nse** scripts which uses fingerprinting to identify **wolfSSH v1.4.7** which contains an integer overflow vulnerability with assigned **CVE-2022-32073.** Program can be run on any machine which has following prerequisites installed: **nmap** and also **python3** along with necessary libraries. 

### Run the program with following commands
To see options and description run the program with the following command. 

    python3 scanner_for_CVE-2022-32073.py --help
    
To run the program on a given address or address range and scan all ports on each host use the following command

    python3 scanner_for_CVE-2022-32073.py -a IP
    
To run the program on a given address or address range and scan given port or port range on each host use the following command
    
    python3 scanner_for_CVE-2022-32073.py -a IP -p PORTS 

### Sample usage and output
The screenshot shows sample use of the programs fingerprinting ability and output formatting on a different version of SSH.

![sample progr. usage](/sample_usage.png "Sample use of the programm on a different version of SSH.")

### Resources

For more info refer to the Documentation.pdf or refer to the https://nmap.org/. 






