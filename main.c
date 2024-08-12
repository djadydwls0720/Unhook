#include "Stealth.h"


int main(int argc, char* argv[]) {


	UnHook(L"explorer.exe","NtQueryDirectoryFile");
}