#include <stdio.h>
#include <stdlib.h>

struct exc { };

class A {
  volatile int i;
public:
  A();
  ~A();
};

// noinline
A::A() { i++; }
A::~A() { i--; }

class B {
  volatile int i;
public:
  B();
  ~B();
};

B::B() { i++; }
B::~B() { i--; }

class C {
  volatile int i;
public:
  C();
  ~C();
};

C::C() { i++; }
C::~C() { i--; }

extern void foo();
extern void bar();
extern void baz();
extern void catch_exc(int i);

extern void foo1();
extern void foo2();
extern void foo3();
extern void foo4();
extern void foo5();

extern void bar1();
extern void bar2();
extern void bar3();

void foo1() { foo2(); }
void foo2() { foo3(); }

void foo3() {
  try {
    foo4();
  } catch (const exc& e) {
    throw;
  }
}

void foo4() { C c; foo5(); }
void foo5() { throw exc(); }

void foo() {
  try {
    foo1();
  } catch (const exc& e) {
    B b;
    throw;
  }
}

void bar1() { bar2(); }
void bar2() { bar3(); }
void bar3() { C c; throw exc(); }

void bar() {
  try {
    B b;
    bar1();
  } catch (const exc& e) {
    catch_exc(2);
  }
}

void baz() { static volatile int n; n++; }

void catch_exc(int i)
{
  if (i == 1)
    bar();
  else
    baz();
}

int main(int argc, char *argv[]) {
  try {
    A a;
    foo();
  } catch (const exc& e) {
    catch_exc(1);
  }
  return 0;
}
