struct exc { };

void foo() {
  try {
    throw exc();
  } catch (const exc& e) {
    throw;
  }
}

int bar() {
  static volatile int n;

  return n++;
}

int main() {
  try {
    foo();
  } catch (const exc& e) {
    bar();
  }
  return 0;
}
