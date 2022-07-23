#include "s-libexcept.hpp"
#include <exception>
#include <stdexcept>

class YYY {
    public:
	YYY()
	{
		throw std::runtime_error("YYY exception");
	}
	~YYY()
	{
	}
};

int main(int argc, char *argv[])
{
	try {
		XXX xxx;
	} catch (...) {
	}

	try {
		YYY yyy;
	} catch (...) {
	}
	return 0;
}
