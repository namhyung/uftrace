#include <iostream>

using namespace std;

static volatile int n;

void foo()
{
  n++;
}

void bar()
{
  n--;
}

void oops()
{
  throw exception();
}

int test()
{
  int r = 0;

  try
  {
    oops();
  }
  catch (exception& e)
  {
    r = 1;
  }
  return r;
}

int main()
{
  int r;

  foo();
  r = test();
  bar();

  return !(r == 1);
}
