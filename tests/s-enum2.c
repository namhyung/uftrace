static int cnt;

enum memory_order_modifier {
	zero = 0,
	memory_order_mask = 0x0ffff,
	memory_order_modifier_mask = 0xffff0000,
	memory_order_hle_acquire = 0x10000,
	memory_order_hle_release = 0x20000
};

__attribute__((noinline)) void foo(enum memory_order_modifier m)
{
	if (m != zero)
		cnt++;
}

int main()
{
	foo(memory_order_mask);
	foo(memory_order_modifier_mask);
	foo(memory_order_hle_acquire);
	foo(memory_order_hle_release);
	return cnt == 4 ? 0 : -1;
}
