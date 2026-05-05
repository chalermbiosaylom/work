Evil Plant
misc Industrial Protocol FCSC 2023



Description
Hello,

From our analyses coupled with our satellite records, we have confirmation that the target, under the guise of being a vaccine production plant, is in fact a toxic liquid production plant used for military purposes.

The network reconnaissance carried out tells us that the target is controlled by an industrial programmable logic controller, itself communicating via a SCADA interface by the OPC-UA protocol in binary mode. We exposed the target on the internet via a UMTS implant, which is now accessible on the network:

localhost:4841

A screenshot of the SCADA interface at an undetermined time has also been recovered:

SCADA

Analysis of recovered engineering documents showed that the toxic liquid formula is composed of 16 elements. We do not know the rates used in the formula or the sequencing of the different elements: we call on you to recover them.

It seems that the elements are added to the vat (at the bottom of the screenshot) two by two, but in order to be able to create an effective remedy, we need to know exactly in what order and with what rates the pairs of elements are mixed.MIX

Hurry, time is running out...

Note: The number of the elements in a pair of elements is to be indicated in ascending order (and not in step 2 of the example below), and the corresponding rates in the same order.030c0c03

Example: An example of the flag format to be submitted is given. Suppose the manufacturing process consists of the following three steps:

Step 1: Add 27 units () of element 1 () and 47 units () of element 8 () to the tank.0x1b0x010x2f0x08MIX
Step 2: Add 95 units () of element 12 () and 141 units () of element 3 () to the tank.0x5f0x0c0x8d0x03MIX
Step 3: Add 230 units () of element 5 () and 177 units () of element 16 () to the tank.0xe60x050xb10x10MIX
The flag to be submitted would be , where all values are expressed in hexadecimal notation.FCSC{01081b2f030c8d5f0510e6b1}

Files
docker-compose.yml
Author

Ludo
Instructions
To get started, download the docker-compose.yml file:
curl https://hackropole.fr/challenges/fcsc2023-misc-evil-plant/docker-compose.public.yml -o docker-compose.yml
Run the test by running in the same folder:
docker compose up
Access the test at localhost:4841 (OPC-UA protocol).
⚠️ Important: You must resolve the challenge by interacting with the Docker container through the exposed network port. Any other interaction is not considered a valid resolution.
