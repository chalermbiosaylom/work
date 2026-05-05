Masterglob Solution for Evil Plant
misc Industrial Protocol

January 11, 2025


Table of Contents
Analysis
Solution
Analysis
The description talks about the OPC-UA protocol. So we can already simply test whether it is possible to connect to the server provided in the docker on the indicated port (4841).

This protocol can be used to encrypt/sign all exchanges, and may require authentications to connect. Fortunately, the server here accepts anonymous connections and allows data to be read.

Solution
The easiest way is to use an OPC-UA client to observe the server data and deduce the mixes... I used UA Expert (with the port given in the description):

We create a new connection (with the prefix normalized by OPC-UA): or for example (access from Windows to a Docker running in a VM)opc.tcp://localhost:4841opc.tcp://192.168.1.248:4841
Once connected, you can see different variables. Apparently, the "Vxx" variables refer to the valves (we don't really need them...), and the variables seem to refer to the meters of the amount of liquid remaining in each tank.Exx
The program shows the order of the tanks used (1 & 3 then 7 & 11 and...), so you just have to note the amount of liquid that is removed during each step to know the value to use. (You can see that each tank is only used once, which makes the task rather simple)
All you have to do is (with UAExpert) to drag for example and from the left window into the "DataAcess View" window, and the data is displayed Live. As soon as they change, you just have to calculate the difference.E1E3
To do nothing by hand, I put all this in a spreadsheet, and with , and (yes, trap...) the solution appears by itself.CONCATDECHEXMINUSCULE
