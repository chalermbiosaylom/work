class badcircuit:
    def __init__(self):
        self.o_a = False
        self.o_b = False
        self.o_c = False
        self.o_d = False

    def __and(self, a: bool, b: bool) -> bool:
        return a and b

    def __or(self, a: bool, b: bool) -> bool:
        return a or b

    def __xor(self, a: bool, b: bool) -> bool:
        return a != b

    def __output(self) -> str:
        return (
            ("1" if self.o_a else "0")
            + ("1" if self.o_b else "0")
            + ("1" if self.o_c else "0")
            + ("1" if self.o_d else "0")
        )

    def __init_inputs(self, input: str) -> None:
        self.i_a = input[0] == "1"
        self.i_b = input[1] == "1"
        self.i_c = input[2] == "1"
        self.i_d = input[3] == "1"
        self.i_e = input[4] == "1"
        self.i_f = input[5] == "1"
        self.i_g = input[6] == "1"
        self.i_h = input[7] == "1"

    def __set_output_a(self) -> None:
        self.o_a = self.__xor(
            self.__or(
                self.__and(
                    self.__or(
                        self.__and(self.__and(self.i_d, self.i_h), self.i_c),
                        self.__or(
                            self.__and(self.__and(self.i_d, self.i_h), self.i_g),
                            self.__and(self.i_c, self.i_g),
                        ),
                    ),
                    self.i_b,
                ),
                self.__or(
                    self.__and(self.__and(self.i_d, self.i_h), self.i_g),
                    self.__and(self.i_b, self.i_f),
                ),
            ),
            self.__xor(self.i_a, self.i_e),
        )

    def __set_output_b(self) -> None:
        self.o_b = self.__xor(
            self.__or(
                self.__and(self.__and(self.i_d, self.i_h), self.i_c),
                self.__or(
                    self.__and(self.__and(self.i_d, self.i_h), self.i_g),
                    self.__and(self.i_c, self.i_g),
                ),
            ),
            self.__xor(self.i_b, self.i_f),
        )

    def __set_output_c(self) -> None:
        self.o_c = self.__xor(
            self.__and(self.i_d, self.i_h),
            self.__xor(self.i_c, self.i_g),
        )

    def __set_output_d(self) -> None:
        self.o_d = self.__xor(self.i_d, self.i_h)

    def run(self, input: str = "00000000") -> str:
        self.__init_inputs(input)

        self.__set_output_a()
        self.__set_output_b()
        self.__set_output_c()
        self.__set_output_d()

        return self.__output()

if __name__ == "__main__":
    circuit = badcircuit()
    input = "11100100"

    print(circuit.run(input))
