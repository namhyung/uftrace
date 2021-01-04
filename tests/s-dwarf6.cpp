#include <string>
#include <vector>

std::string addString(std::string dst, const char *src)
{
  return dst + src;
}

std::vector<int> addItem(std::vector<int> v, int n)
{
  v.push_back(n);
  return v;
}

int main(int argc, char *argv[])
{
  std::vector<int> v = { 1, 2, 3 };
  int n = 0;
  const char *s = "test";

  if (argc > 1)
    n = atoi(argv[1]);
  if (argc > 2)
    s = argv[2];

  if (addString(" uftrace ", s) != " uftrace test")
    return 1;
  if (addItem(v, n)[3] != 0)
    return 1;

  return 0;
}
