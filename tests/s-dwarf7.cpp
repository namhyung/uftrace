#include <vector>

__attribute__((noinline)) int compare_iters(std::vector<int>::iterator beg,
					    std::vector<int>::iterator end)
{
	return beg == end;
}

int main()
{
	std::vector<int> v(3, 1);
	return compare_iters(v.begin(), v.end());
}
