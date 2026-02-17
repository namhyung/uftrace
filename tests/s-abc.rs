use std::process;

fn a() -> u32 {
	return b();
}

fn b() -> u32 {
	return c();
}

fn c() -> u32 {
	return process::id();
}

fn main() {
	a();
}
