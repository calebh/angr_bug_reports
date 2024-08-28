void test() {
	// Here we expect primask to be 1 after execution
	asm ("cpsid i");
}

void test2() {
	// Here we expect primask to be 1 after execution
	asm ("movs r3, #01\n"
		 "msr primask, r3");
}

void test3() {
	// Here we expect primask to be 0 after execution
	asm ("movs r3, #01\n"
		 "msr primask, r3\n"
		 "cpsie i");
}

void test4() {
	// Here we expect primask to be 0 after execution
	asm ("cpsid i\n"
		 "cpsie i");
}