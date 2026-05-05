You are given the logic circuit in the image circuit.png, and you are asked to provide the binary output corresponding to the input (x0, x1, x2, x3, x4) = (1, 0, 0, 1, 1). Enclose your answer in boxes FCSC{}to obtain the flag.

As an example, (x0, x1, x2, x3, x4) = (1, 0, 0, 0, 0)give (y0, y1, y2, y3, y4) = (1, 0, 1, 0, 0), which would give FCSC{10100}as a flag.
https://hackropole.fr/challenges/fcsc2022-hardware-ne-pas-jeter-leponge/public/circuit.png
Circuit analysis
The logic circuit studied here consists of:

5 AND gates, one of whose entrances is reversed


5-door XOR


Note: it should be noted here that, contrary to the usual notation, x0is the most significant bit and is x4the least significant bit.

Circuit simulation in Verilog
Verilog is a hardware description language (HDL) used to model and design digital electronic systems. It was created by Phil Moorby at Gateway Design Automation in 1984.

Route description
The file circuit.vis edited in Visual Studio Code with the Verilog extension by Masahiro Hiramori.

module circuit_test;
   // Déclaration des registres et fils
   reg [0:4] x;      // Registre d'entrée sur 5 bits (x0 est MSB)
   wire [0:4] z, w, y; // Fils intermédiaires et de sortie
   reg [0:4] y_exp;    // Registre pour stocker la sortie attendue lors des tests

   // Portes AND : détectent les transitions 1->0 entre bits adjacents cycliques
   // x[4] et x[0] sont considérés comme adjacents (structure circulaire)
   and(w[0], x[4], !x[0]);  // w[0] = 1 si x[4]=1 et x[0]=0
   and(w[1], x[0], !x[1]);  // w[1] = 1 si x[0]=1 et x[1]=0
   and(w[2], x[1], !x[2]);  // w[2] = 1 si x[1]=1 et x[2]=0
   and(w[3], x[2], !x[3]);  // w[3] = 1 si x[2]=1 et x[3]=0
   and(w[4], x[3], !x[4]);  // w[4] = 1 si x[3]=1 et x[4]=0

   // Portes XOR : modifient les bits d'entrée selon les transitions détectées
   // Le bit de sortie y[i] est modifié si une transition a été détectée à la position précédente
   xor(y[0], w[4], x[0]);  // y[0] inversé si transition avant x[0]
   xor(y[1], w[0], x[1]);  // y[1] inversé si transition avant x[1]
   xor(y[2], w[1], x[2]);  // y[2] inversé si transition avant x[2]
   xor(y[3], w[2], x[3]);  // y[3] inversé si transition avant x[3]
   xor(y[4], w[3], x[4]);  // y[4] inversé si transition avant x[4]

   initial begin
       // Bloc de test du circuit

       // Premier test avec valeurs connues en entrée et sortie
       x = 5'b10000;      // Entrée : 10000
       y_exp = 5'b10100;  // Sortie attendue : 10100
       #10;               // Attente de 10 unités de temps
       // Affichage des résultats
       $display("Test 1 results:");
       $display("Input (x0,x1,x2,x3,x4) = %b", x);
       $display("Output (y0,y1,y2,y3,y4) = %b", y);

       // Vérification du résultat
       if (y !== y_exp)
           $display("Test 1 failed: y incorrect\n val %b\n exp %b", y, y_exp);
       else
           $display("Test 1 passed: y = %b", y);

       // Second test avec sortie inconnue
       x = 5'b10011;      // Nouvelle entrée : 10011
       #10;               // Attente de 10 unités de temps
       // Affichage des résultats
       $display("Test 2 results:");
       $display("Input (x0,x1,x2,x3,x4) = %b", x);
       $display("Output (y0,y1,y2,y3,y4) = %b", y);
       $display("Test complete");
   end

   // Moniteur pour suivre l'évolution des signaux dans le temps
   initial
       $monitor("Time=%0t\nIN  x=%b\n    w=%b\nOUT y=%b\n", $time, x, w, y);
endmodule
This code implements a test circuit that:

Detects 1->0 transitions between adjacent bits (including between the last and first bits)
Use these detections to modify the following bits via XOR operations.
Includes two test cases to verify the circuit behavior
The circuit could be used for data encoding/decoding or detecting specific patterns in a binary sequence.

Circuit simulation
The Icarus Verilog software allows you to perform the simulation https://steveicarus.github.io/iverilog/index.html

Example of use on Kali (a Debian-based distribution):

$ sudo apt install iverilog
$ iverilog -o circuit circuit.v
$ vvp circuit
Time=0
IN  x=10000
    w=01000
OUT y=10100

Test 1 results:
Input (x0,x1,x2,x3,x4) = 10000
Output (y0,y1,y2,y3,y4) = 10100
Test 1 passed: y = 10100
Time=10
IN  x=10011
    w=01000
OUT y=10111

Test 2 results:
Input (x0,x1,x2,x3,x4) = 10011
Output (y0,y1,y2,y3,y4) = 10111
Test complete
The flag is therefore FCSC{10111}.

Circuit simulation in VHDL
VHDL (VHSIC Hardware Description Language) is a hardware description language created in the 1980s by the U.S. Department of Defense. The term VHSIC stands for “Very High Speed ​​Integrated Circuit”.

Route description
The file circuit.vhdis edited with Visual Studio Code (+ VHDL extension by Pu Zhao)

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;


-- Entité principale
entity circuit_test is
end circuit_test;

-- Architecture du circuit
architecture Behavioral of circuit_test is
    -- Déclaration des signaux
    signal x : std_logic_vector(0 to 4);      -- Entrée
    signal w : std_logic_vector(0 to 4);      -- Signal intermédiaire (AND)
    signal y : std_logic_vector(0 to 4);      -- Sortie
    signal y_exp : std_logic_vector(0 to 4);  -- Sortie attendue


begin
    -- Portes AND
    w(0) <= x(4) and (not x(0));
    w(1) <= x(0) and (not x(1));
    w(2) <= x(1) and (not x(2));
    w(3) <= x(2) and (not x(3));
    w(4) <= x(3) and (not x(4));

    -- Portes XOR
    y(0) <= w(4) xor x(0);
    y(1) <= w(0) xor x(1);
    y(2) <= w(1) xor x(2);
    y(3) <= w(2) xor x(3);
    y(4) <= w(3) xor x(4);

    -- Processus de test
    test_proc: process
    begin
        -- Test 1 avec valeurs connues
        x <= "10000";
        y_exp <= "10100";
        wait for 10 ns;

        -- Affichage des résultats
        report "Test 1 results:";
        report "Input (x0,x1,x2,x3,x4) = " & to_string(x);
        report "Output (y0,y1,y2,y3,y4) = " & to_string(y);

        -- Vérification
        if (y /= y_exp) then
            report "Test 1 failed: y incorrect" severity ERROR;
            report "Got: " & to_string(y);
            report "Expected: " & to_string(y_exp);
        else
            report "Test 1 passed: y = " & to_string(y);
        end if;

        -- Test 2
        x <= "10011";
        wait for 10 ns;

        report "Test 2 results:";
        report "Input (x0,x1,x2,x3,x4) = " & to_string(x);
        report "Output (y0,y1,y2,y3,y4) = " & to_string(y);
        report "Test complete";

        wait;
    end process;

    -- Processus de monitoring
    monitor_proc: process
    begin
        report "Time=" & time'image(now) & " ns" &
               " IN x=" & to_string(x) &
               " w=" & to_string(w) &
               " OUT y=" & to_string(y);
        wait on x, w, y;
    end process;

end Behavioral;
Circuit simulation
Example of its use ghdlon Kali (a Debian-based distribution):

sudo apt install ghdl gtkwave
File analysis

$ ghdl -a --std=08 circuit.vhd
Note: This parameter --std=08is passed to access functions defined in the VHDL 2008 standard ( to_stringamong others).

Development of the entity

$ ghdl -e --std=08 circuit_test
Simulation launched

$ ghdl -r --std=08 circuit_test
circuit.vhd:83:9:@0ms:(report note): Time=0 fs ns IN x=XXXXX w=XXXXX OUT y=XXXXX
circuit.vhd:83:9:@0ms:(report note): Time=0 fs ns IN x=10000 w=XXXXX OUT y=XXXXX
circuit.vhd:83:9:@0ms:(report note): Time=0 fs ns IN x=10000 w=01000 OUT y=XXXXX
circuit.vhd:83:9:@0ms:(report note): Time=0 fs ns IN x=10000 w=01000 OUT y=10100
circuit.vhd:55:9:@10ns:(report note): Test 1 results:
circuit.vhd:56:9:@10ns:(report note): Input (x0,x1,x2,x3,x4) = 10000
circuit.vhd:57:9:@10ns:(report note): Output (y0,y1,y2,y3,y4) = 10100
circuit.vhd:65:13:@10ns:(report note): Test 1 passed: y = 10100
circuit.vhd:83:9:@10ns:(report note): Time=10000000 fs ns IN x=10011 w=01000 OUT y=10100
circuit.vhd:83:9:@10ns:(report note): Time=10000000 fs ns IN x=10011 w=01000 OUT y=10111
circuit.vhd:72:9:@20ns:(report note): Test 2 results:
circuit.vhd:73:9:@20ns:(report note): Input (x0,x1,x2,x3,x4) = 10011
circuit.vhd:74:9:@20ns:(report note): Output (y0,y1,y2,y3,y4) = 10111
circuit.vhd:75:9:@20ns:(report note): Test complete
The flag is back again FCSC{10111}.

Verilog / VHDL Comparison
The main difference between Verilog and VHDL concerns the declaration and addressing of bit vectors:

In VHDL:

-- Format : (borne_gauche TO/DOWNTO borne_droite)
signal compteur : std_logic_vector(7 downto 0);  -- 8 bits, MSB=7, LSB=0
signal data : std_logic_vector(0 to 7);          -- 8 bits, MSB=0, LSB=7
downto: count from the largest value to the smallest
to: count from the smallest value to the largest
The choice impacts the bit order (MSB/LSB)
More verbose but more explicit
In Verilog:

// Format : [borne_gauche:borne_droite]
reg [7:0] compteur;    // 8 bits, MSB=7, LSB=0
reg [0:7] data;        // 8 bits, MSB=0, LSB=7
Simply use :between the terminals
The first limit is always the MSB (Most Significant Bit)
The second limit is always the LSB (Least Significant Bit)
More concise but less explicit about the direction
Concrete example:

-- VHDL
signal a : std_logic_vector(3 downto 0);  -- a = "1101" : MSB=1, LSB=1
// Verilog équivalent
reg [3:0] a;    // a = 4'b1101 : MSB=1, LSB=1
In summary, VHDL is more explicit with its keywords to/ downtowhile Verilog uses a more compact notation with :. This difference reflects the general philosophy of the two languages: VHDL tends to be more verbose but clearer, while Verilog prioritizes conciseness.

Possible roles of the circuit under study
Based on the analysis of the circuit's behavior, here are the possible roles:

Data encoding/decoding :

Encoding for serial transmission
Reversible data transformation
Protection against transmission errors
Scrambling/descrambling
Pattern detection :

1→0 Transition Detection
Identification of specific sequences
Data format validation
Protocol violation detection
Synchronization :

Marking of the beginnings of the frame
Generation of synchronization signals
Maintaining bit synchronization
Boundary detection
Specific applications :

Serial communication protocols

Frame start/end detection
Data validity verification
Inserting control bits
Security systems

Simple data scrambling
Detection of forbidden sequences
Basic copy protection
Signal processing

Front detection
Glitch filtering
Clock reconstruction
Data compression

Repetitive pattern detection
Sequence encoding
Bandwidth optimization
