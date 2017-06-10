#include <string>

std::string s[] = {"Hello", "World!", "std::string support is done!"};

__attribute__((noinline))
void std_string_arg(std::string& s)
{
  s = s;
}

__attribute__((noinline))
std::string std_string_ret(int index)
{
  return s[index];
}

int main()
{
  std_string_arg(s[0]);
  std_string_arg(s[1]);
  std_string_arg(s[2]);

  std_string_ret(0);
  std_string_ret(1);
  std_string_ret(2);
}
