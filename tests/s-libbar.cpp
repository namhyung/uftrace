class Parent {
public:
  virtual int func(int n);
  virtual int bar(int n);
};

int Parent::bar(int n)
{
  return func(n ?: 1);
}

int Parent::func(int n)
{
  return 0;
}
