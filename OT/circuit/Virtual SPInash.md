You’ve just found a mysterious circuit board on your desk, its component references partially erased. But what secret could it be hiding?

You connect a serial port to the 4 pins at its end. The board’s serial port is exposed on port 4000.

Frontside

Backside

Files
docker-compose.yml
Author

erdnaxe
Challenge Instructions
First, download docker-compose.yml:
curl https://hackropole.fr/challenges/fcsc2024-hardware-virtual-spinash/docker-compose.public.yml -o docker-compose.yml
Launch the challenge by executing in the same folder:
docker compose up
Then, in another console, access the challenge with Netcat:
nc localhost 4000
⚠️ Important: You must solve the challenge by interacting with the Docker container through the exposed network port. Any other way is not considered valid.

In case you encounter problems, please consult the FAQ.

Solution de cartoone222 pour Virtual SPInash
hardware circuit

15 avril 2024




Pour résoudre ce challenge, on dispose de 3 éléments :

deux images, qui correspondent aux 2 faces d’un circuit imprimé
un accès à un port série.
On commence par se connecter au port série. On obtient ce résultat :

MicroPython v1.22.2 on 1980-01-01; Mysterious FCSC board with STM32F405RG
Type "help()" for more information.
>>>
On constate donc que l’on est sur un microcontrôleur STM32F405RG qui tourne sous Micropython. Ça tombe bien : j’ai une petite expérience avec les Rasberry PI Pico.

On a aussi les deux images du PCB. On a deux puces montées en surface, quelque condensateurs, un quartz, un bouton, un port série, et 10 fiches mâles… rien de bien foufou !!

On a identifié le micro-contrôleur. Pour la deuxième puce, on a une référence IS25LP080D. Après recherche, c’est une mémoire flash qui communique en série.

Première étape, on récupère les Datasheets pour avoir le pin out de la mémoire :



Voici un tableau qui explique les acronymes :

PIN	Fonction
Vcc	alimentation +
GND	alimentation -
WP#	protection en écriture
SCK	signal d’horloge
CE#	chip enable
HOLD#	on s’en fiche, c’est pas connecté
SO	signal output
SI	signal input
On peut identifier le sens des composants avec la flèche blanche qui pointe la broche 1.

On va maintenant chercher à identifier quelles broches du micro contrôleur sont connectées à quelles broches de la mémoire flash.



virtual-spinash-analyse

Dans la mesure où les pins du micro-contrôleur sont numérotés dans le sens inverse des aiguilles d’une montre, on a les correspondances suivantes :

PIN mémoire	PIN microcontroleur
SCK	34
SI/SO	35/36
CE	33
On va maintenant regarder le PIN out du micro-contrôleur dans la documentation. On se rend compte que PB12, PB13, PB14 et PB15 correspondent à SPI2_NSS, SPI2_CSK, SPI2_MISO, SPI2_MOSI.

On constate que la mémoire est branchée sur l’interface SPI-2. (Serial Peripheral Interface)

On passe maintenant à l’exploitation. On va écrire un code Python pour lire la mémoire :

from machine import Pin, SPI

spi2 = SPI(2, baudrate=10000000)

cs = Pin("PB12", Pin.OUT)
cs.value(0)

spi2.write(b'\x03') # commande d'ecriture
spi2.write(bytearray([(0 >> 16) & 0xFF, (0 >> 8) & 0xFF, 0 & 0xFF]))
data = bytearray(1024)
spi2.readinto(data)

print(data)
et l’on obtient le flag qui est donc :

FCSC{a8937c95944625276140d65539299e81e179ec2293417010817a7a595fca987f}
