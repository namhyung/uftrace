class Parent {
public:
  virtual int func(int n);
  virtual int bar(int n);
};

class Child : public Parent {
public:
  virtual int func(int n);
};

int Child::func(int n)
{
  return 100;
}

extern "C" Parent* creat()
{
  return new Child;
}
