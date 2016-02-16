#include <stdlib.h>

namespace ns {
	namespace ns1 {
		class foo {
		private:
			int size_;
			void *bar1(void);
			void *bar2(void);
			void *bar3(void);

		public:
			foo(int size);
			void bar(void);
		};

		foo::foo(int size)
		{
			size_ = size;
		}

		void * foo::bar1(void)
		{
			return bar2();
		}

		void * foo::bar2(void)
		{
			return bar3();
		}

		void * foo::bar3(void)
		{
			return malloc(size_);
		}

		void foo::bar(void)
		{
			free(bar1());
		}
	}

	namespace ns2 {
		class foo {
		private:
			int size_;
			void *bar1(void);
			void *bar2(void);
			void *bar3(void);

		public:
			foo(int size);
			void bar(void);
		};

		foo::foo(int size)
		{
			size_ = size;
		}

		void * foo::bar1(void)
		{
			return bar2();
		}

		void * foo::bar2(void)
		{
			return bar3();
		}

		void * foo::bar3(void)
		{
			return malloc(size_);
		}

		void foo::bar(void)
		{
			free(bar1());
		}
	}
}

int main(int argc, char *argv[])
{
	int n = 0;
	ns::ns1::foo *foo1;
	ns::ns2::foo *foo2;

	foo1 = new ns::ns1::foo(1);
	foo1->bar();
	delete foo1;

	foo2 = new ns::ns2::foo(2);
	foo2->bar();
	delete foo2;

	return 0;
}
