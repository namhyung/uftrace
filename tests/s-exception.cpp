#include <iostream>

using namespace std;

void foo()
{
}

void bar()
{
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
