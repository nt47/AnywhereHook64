#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <intrin.h>
typedef DWORD64 qw;

struct Test {
	qw _ntdll;
	qw _kernel32;
	qw user32;
};


extern "C" void nop1();

extern "C" int printLn(const char* text);

extern "C" int msg(const char* text);

extern "C" void hello();


int printLn(const char* text)
{
	return printf("%s \n", text);
}

int msg(const char* text)
{
	return MessageBoxA(0, text, 0, 0);
}

void MyFunc(bool bCheck)
{
	Test test{ 0 };

	test._ntdll = 0;
	if (bCheck)
	{
		test._ntdll = (qw)GetModuleHandle(L"ntdll.dll");

	}
	test._kernel32 = (qw)GetModuleHandle(L"kernel32.dll");
	nop1();
	test.user32 = (qw)GetModuleHandle(L"user32.dll");

	int a = 8;
	a += 8;
	a += 16;
	a += 24;
	printf("this is MyFunc %llx\n", printLn);
	printf("ntdll is %llx kernel32 is %llx user32 is %llx \n", test._ntdll, test._kernel32, test.user32);

	//hello();

	
}






int main()
{

	while (true)
	{

		MyFunc(true);
		Sleep(3000);
	}
}