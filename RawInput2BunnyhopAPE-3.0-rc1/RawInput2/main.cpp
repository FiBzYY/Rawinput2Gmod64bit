#include <Windows.h>
#include <fstream>
#include <string>
#include <conio.h>
#include <stdio.h>
#include "utils.h"
#include "Detours/src/detours.h"

typedef LRESULT(__thiscall* WindowProcFn)(void*, HWND, UINT, WPARAM, LPARAM);
WindowProcFn oWindowProc;

IInputSystem* g_InputSystem = nullptr;
//CInput* g_Input = nullptr;

typedef bool(__thiscall* GetRawMouseAccumulatorsFn)(void*, int&, int&);
typedef void(__thiscall* GetAccumulatedMouseDeltasAndResetAccumulatorsFn)(void*, float*, float*);
typedef void(__thiscall* ControllerMoveFn)(void*, float, void*);
typedef void(__thiscall* In_SetSampleTimeFn)(void*, float);

GetRawMouseAccumulatorsFn oGetRawMouseAccumulators;
GetAccumulatedMouseDeltasAndResetAccumulatorsFn oGetAccumulatedMouseDeltasAndResetAccumulators;
ControllerMoveFn oControllerMove;
In_SetSampleTimeFn oIn_SetSampleTime;

// https://en.wikipedia.org/wiki/X86_calling_conventions#Microsoft_x64_calling_convention
typedef void(__cdecl* ConMsgFn)(const char*, ...);
ConMsgFn ConMsg;

typedef double(__cdecl* Plat_FloatTimeFn)();
Plat_FloatTimeFn Plat_FloatTime;

int* m_rawinput_cvar;

float mouseMoveFrameTime;

double m_mouseSplitTime;
double m_mouseSampleTime;
float m_flMouseSampleTime;

DWORD haxorThreadID;

bool GetRawMouseAccumulators(int& accumX, int& accumY, double frame_split)
{
	static int* m_mouseRawAccumX = (int*)((uintptr_t)g_InputSystem + 0x5fa0);
	static int* m_mouseRawAccumY = (int*)((uintptr_t)g_InputSystem + 0x5fa4);

	ConMsg("GetRawMouseAccumulators: %d | %d\n", *m_mouseRawAccumX, *m_mouseRawAccumY);

	MSG msg;
	if (frame_split != 0.0 && PeekMessageW(&msg, NULL, WM_INPUT, WM_INPUT, PM_REMOVE))
	{
		do
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		} while (PeekMessageW(&msg, NULL, WM_INPUT, WM_INPUT, PM_REMOVE));
	}

	double mouseSplitTime = m_mouseSplitTime;
	if (mouseSplitTime == 0.0)
	{
		mouseSplitTime = m_mouseSampleTime - 0.01;
		m_mouseSplitTime = mouseSplitTime;
	}

	double mouseSampleTime = m_mouseSampleTime;

	if (abs(mouseSplitTime - mouseSampleTime) >= 0.000001)
	{
		if (frame_split == 0.0 || frame_split >= mouseSampleTime)
		{
			accumX = *m_mouseRawAccumX;
			accumY = *m_mouseRawAccumY;
			*m_mouseRawAccumX = 0;
			*m_mouseRawAccumY = 0;

			m_mouseSplitTime = m_mouseSampleTime;

			return true;
		}
		else if (frame_split >= mouseSplitTime)
		{
			float splitSegment = (frame_split - mouseSplitTime) / (mouseSampleTime - mouseSplitTime);

			accumX = static_cast<int>(splitSegment * (*m_mouseRawAccumX));
			accumY = static_cast<int>(splitSegment * (*m_mouseRawAccumY));

			*m_mouseRawAccumX -= accumX;
			*m_mouseRawAccumY -= accumY;

			m_mouseSplitTime = frame_split;

			return true;
		}
	}

	accumX = accumY = 0;

	return true;
}

__declspec(noinline)
void GetAccumulatedMouseDeltasAndResetAccumulators(CInput* thisptr, float* mx, float* my, float frametime)
{
	//Assert(mx);
	//Assert(my);

	float* m_flAccumulatedMouseXMovement = (float*)((uintptr_t)thisptr + 0xc);
	float* m_flAccumulatedMouseYMovement = (float*)((uintptr_t)thisptr + 0x10);

	int m_rawinput = *m_rawinput_cvar;

	ConMsg("GetAccumulatedMouseDeltasAndResetAccumulators: %.3f | %.3f | %d\n", *(float*)m_flAccumulatedMouseXMovement, *(float*)m_flAccumulatedMouseYMovement, m_rawinput);

	if (m_flMouseSampleTime > 0.0)
	{
		int rawMouseX, rawMouseY;
		if(m_rawinput != 0)
		{
			if (m_rawinput == 2 && frametime > 0.0)
			{
				m_flMouseSampleTime -= MIN(m_flMouseSampleTime, frametime);
				GetRawMouseAccumulators(rawMouseX, rawMouseY, Plat_FloatTime() - m_flMouseSampleTime);
			}
			else
			{
				GetRawMouseAccumulators(rawMouseX, rawMouseY, 0.0);
				m_flMouseSampleTime = 0.0;
			}
		}
		else
		{
			rawMouseX = *(float*)m_flAccumulatedMouseXMovement;
			rawMouseY = *(float*)m_flAccumulatedMouseYMovement;
		}

		*(float*)m_flAccumulatedMouseXMovement = 0.0;
		*(float*)m_flAccumulatedMouseYMovement = 0.0;

		*mx = (float)rawMouseX;
		*my = (float)rawMouseY;
	}
	else
	{
		*mx = 0.0;
		*my = 0.0;
	}
}

bool __fastcall Hooked_GetRawMouseAccumulators(void* thisptr, int& accumX, int& accumY)
{
	return GetRawMouseAccumulators(accumX, accumY, 0.0);

	//GetRawMouseAccumulators(accumX, accumY, 0.0);
	//return oGetRawMouseAccumulators(thisptr, accumX, accumY);
}

LRESULT __fastcall Hooked_WindowProc(void* thisptr, HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ConMsg("WindowProc: %.3f\n", m_mouseSampleTime);

	switch (uMsg)
	{
	case WM_INPUT:
		{
			m_mouseSampleTime = Plat_FloatTime();
			break;
		}
	case WM_SYSKEYDOWN:
	case WM_KEYDOWN:
		{
			// bit 30: "The previous key state. The value is 1 if the key is down before the message is sent, or it is zero if the key is up."
			if ((lParam & 0x40000000) == 0) {
				if (wParam == VK_F5 || wParam == VK_F6 || wParam == VK_F7) {
					PostThreadMessageA(haxorThreadID, WM_HOTKEY, wParam - VK_F5 + 1, 0);
				}
			}
			break;
		}
	}

	return oWindowProc(thisptr, hwnd, uMsg, wParam, lParam);
}

void __fastcall Hooked_GetAccumulatedMouseDeltasAndResetAccumulators(CInput* thisptr, float* mx, float* my)
{
	GetAccumulatedMouseDeltasAndResetAccumulators(thisptr, mx, my, mouseMoveFrameTime);

	mouseMoveFrameTime = 0.0;

	ConMsg("test: %.5f\n", mouseMoveFrameTime);

	//oGetAccumulatedMouseDeltasAndResetAccumulators(thisptr, mx, my);
}

void __fastcall Hooked_ControllerMove(void* thisptr, float ft, void* cmd)
{
	mouseMoveFrameTime = ft;

	oControllerMove(thisptr, mouseMoveFrameTime, cmd);
}

void __fastcall Hooked_IN_SetSampleTime(void* thisptr, float frametime)
{
	m_flMouseSampleTime = frametime;

	oIn_SetSampleTime(thisptr, frametime);
}

BOOL IsProcessRunning(DWORD processID)
{
	HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, processID);
	DWORD ret = WaitForSingleObject(process, 0);
	CloseHandle(process);
	return ret == WAIT_TIMEOUT;
}

// https://stackoverflow.com/questions/10866311/getmessage-with-a-timeout/10866328#10866328
BOOL GetMessageWithTimeout(MSG* msg, UINT to)
{
	BOOL res;
	UINT_PTR timerId = SetTimer(NULL, NULL, to, NULL);
	res = GetMessage(msg, NULL, 0, 0);
	KillTimer(NULL, timerId);
	if (!res)
		return FALSE;
	if (msg->message == WM_TIMER && msg->hwnd == NULL && msg->wParam == timerId)
		return FALSE; //TIMEOUT! You could call SetLastError() or something...
	return TRUE;
}

DWORD InjectionEntryPoint(DWORD processID)
{
	LoadLibraryA("VCRUNTIME140.dll");

	haxorThreadID = GetCurrentThreadId();

	// Search for CallWindowProc[A] in inputsystem.dll. You should find it called from `CInputSystem::ChainWindowMessage()` (which is called by `CInputSystem::WindowProc()`).
	// On x64 (and maybe x32) you'll probably find `ChainWindowMessage` inlined into `CInputSystem::WindowProc()`.
	oWindowProc = (WindowProcFn)(FindPattern("inputsystem.dll", "48 89 54 24 10 53 55 41 55 41 56 41 57"));

	auto inputsystem_factory = reinterpret_cast<CreateInterfaceFn>(GetProcAddress(GetModuleHandleA("inputsystem.dll"), "CreateInterface"));
	g_InputSystem = reinterpret_cast<IInputSystem*>(inputsystem_factory("InputSystemVersion001", nullptr));
	//g_Input = **reinterpret_cast<CInput***>(FindPattern("client.dll", "8B 0D ? ? ? ? 8B 01 FF 60 44") + 2);

	/*
	This is kind of a hassle to find and I went a very round-about way for it.
	- In client.dll:
	  Find CInput::ActivateMouse() by searching for a call to the winapi SystemParametersInfoA.
      (ActivateMouse() is probably the first function that references SystemParametersInfoA).
	- At the bottom of ActivateMouse(): grab the `(**(code **)(*DAT_181074218 + 0x138))(DAT_181074218,local_res10,local_res8);`
	  The DAT_181074218 is the g_InputSystem / `inputsystem` pointer.
	    (Rename it to `g_InputSystem` because we're going to use it again to find GetAccumulatedMouseDeltasAndResetAccumulators()!)
	  The 0x138 is the vtable byte offset. 0x138 / 8 = 39.
	- In inputsystem.dll:
	  Search for "CInputSystem::AttachToWindow: Cannot attach" to find CInputSystem::AttachToWindow().
	  Use the references to AttachToWindow() to find the CInputSystem vtable.
	- Go to the vtable[39] (40th) function and you should find GetRawMouseAccumulators. Hopefully.
	/*/
	oGetRawMouseAccumulators = (GetRawMouseAccumulatorsFn)(FindPattern("inputsystem.dll", "8B 81 A0 5F 00 00 89 02"));
	/*
	In client.dll:
	Use the g_InputSystem value we found and then search for references where they use the vtable byte offset for GetRawMouseAccumulators() again!
	It was one of the last references for me.
	*/
	/*
	Also the call to GetAccumulatedMouseDeltasAndResetAccumulators that matters is inlined inside of CInput::MouseMove() so that's annoying....

	*/
	oGetAccumulatedMouseDeltasAndResetAccumulators = (GetAccumulatedMouseDeltasAndResetAccumulatorsFn)(FindPattern("client.dll", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 05 ? ? ? ? 48 8B D9 48 8D 0D"));
	// actually the instruction is a MOV here 😇
	m_rawinput_cvar = (int*)((uintptr_t)AddrFromLea((uintptr_t)oGetAccumulatedMouseDeltasAndResetAccumulators + 35) + 0x30); // x30 x20?
	// TODO: This is AWFUL!!!! Will probably break one day... just use Safetyhook inline/mid-function hooks when that happens and hope for the best lol...
	/*
		Thunk:
		push rcx
		push rdx
		push r8
		push r9
		push r10
		push r11

		push r15
		mov r15, rsp

		sub rsp, 64
		and rsp, -32

		lea rdx, [rsp+0x30]     ; param_2 => [RSP + 0x30]
		lea r8,  [rsp+0x48]     ; param_3 => [RSP + 0x48]

		sub rsp, 32

		mov rcx, rbx            ; RCX = this
		mov rax, 0x1111111111111111
		call rax                ; Call the original function

		movss xmm0, [rsp+0x30]  ; Load first float result
		movss xmm1, [rsp+0x48]  ; Load second float result

		mov rsp, r15
		pop r15

		pop r11
		pop r10
		pop r9
		pop r8
		pop rdx
		pop rcx

	*/
	char patch[89 + 1] =
		"\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x41\x57"  // push registers
		"\x49\x89\xE7"                                      // mov r15, rsp
		"\x48\x83\xEC\x40\x48\x83\xE4\xE0"                  // sub rsp, 64; and rsp, -32
		"\x48\x8D\x54\x24\x30"                              // lea rdx, [rsp + 0x30] (param_2)
		"\x4C\x8D\x44\x24\x48"                              // lea r8,  [rsp + 0x48] (param_3)
		"\x48\x83\xEC\x20"                                  // sub rsp, 32
		"\x48\x89\xD9"                                      // mov rcx, rbx (this)
		"\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11"          // mov rax, Hooked_GetAccumulatedMouseDeltasAndResetAccumulators
		"\xFF\xD0"                                          // call rax
		"\xF3\x0F\x10\x44\x24\x30"                          // movss xmm0, [rsp + 0x30] (mouse X)
		"\xF3\x0F\x10\x4C\x24\x48"                          // movss xmm1, [rsp + 0x48] (mouse Y)
		"\x4C\x89\xFC"                                      // mov rsp, r15
		"\x41\x5F\x41\x5B\x41\x5A\x41\x59\x41\x58"          // pop r15, r11, r10, r9, r8
		"\x5A\x59"                                          // pop rdx, rcx
		"\x90\x90\x90\x90\x90\x90\x90\x90\x90";             // NOPs to pad to 89 bytes

	*(void**)(patch + 41) = Hooked_GetAccumulatedMouseDeltasAndResetAccumulators;
	char GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original[89]{};
	auto GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove = (void*)FindPattern("client.dll", "F3 0F 10 57 0C F3 0F 10 5F 10");
	DWORD GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_protect;
	VirtualProtect(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove, sizeof(patch) - 1, PAGE_EXECUTE_READWRITE, &GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_protect);
	memcpy(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original, GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove, sizeof(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original));
	memcpy(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove, patch, sizeof(patch) - 1);
	/*
	In client.dll:
	Find CInput::JoyStickMove() by searching for the FLOAT (f32!!!) 14000.0.
	Go to function that calls JoyStickMove() and bam you're inside CInput::ControllerMove()!
	*/
	oControllerMove = (ControllerMoveFn)(FindPattern("client.dll", "48 89 5C 24 ? 57 48 83 EC 30 80 B9 ? ? ? ? 00 49 8B F8 0F 29 74 24"));
	/*
	- Find CInput vtable with CInput::ActivateMouse() via winapi SystemParametersInfoA.
	- Go up 2 functions in the table to find CInput::IN_SetSampleTime()
	*/
	//oIn_SetSampleTime = (In_SetSampleTimeFn)(FindPattern("client.dll", "cc f3 0f 11 49 ? c3 cc") + 1);
	oIn_SetSampleTime = (In_SetSampleTimeFn)(FindPattern("client.dll", "f3 0f 11 49 20 c3"));

	uintptr_t tier = (uintptr_t)GetModuleHandleA("tier0.dll");
	ConMsg = (ConMsgFn)(uintptr_t)GetProcAddress((HMODULE)tier, "?ConMsg@@YAXPEBDZZ");

	Plat_FloatTime = (Plat_FloatTimeFn)(uintptr_t)GetProcAddress((HMODULE)tier, "Plat_FloatTime");
	ConMsg("Plat_FloatTime: %.5f\n", Plat_FloatTime());

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)oWindowProc, Hooked_WindowProc);
	DetourAttach(&(PVOID&)oGetRawMouseAccumulators, Hooked_GetRawMouseAccumulators);
	DetourAttach(&(PVOID&)oGetAccumulatedMouseDeltasAndResetAccumulators, Hooked_GetAccumulatedMouseDeltasAndResetAccumulators);
	DetourAttach(&(PVOID&)oControllerMove, Hooked_ControllerMove);
	DetourAttach(&(PVOID&)oIn_SetSampleTime, Hooked_IN_SetSampleTime);

	DetourTransactionCommit();
	//LoadLibraryA("C:\\code\\StrafeAnalyzer\\Release\\strafe analyzer.dll");

	while (IsProcessRunning(processID))
	//while(FindWindowA(NULL, "CS:S RawInput2") != 0)

	//VirtualProtect(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove, sizeof(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original) - 1, GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_protect, &GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_protect);
	//memcpy(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove, GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original, sizeof(GetAccumulatedMouseDeltasAndResetAccumulators_inside_MouseMove_original) - 1);
	DetourTransactionCommit();

	ExitThread(0);
	return 0;
}

//Credits: https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes
void PEInjector(HANDLE targetProcess, DWORD Func(DWORD))
{
	// Get current image's base address
	PVOID imageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	// Allocate a new memory block and copy the current PE image to this new memory block
	PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Allote a new memory block in the target process. This is where we will be injecting this PE
	PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

	// Relocate localImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD relocationEntriesCount = 0;
	PDWORD_PTR patchedAddress;
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (relocationTable->SizeOfBlock > 0)
	{
		relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

		for (DWORD i = 0; i < relocationEntriesCount; i++)
		{
			if (relocationRVA[i].Offset)
			{
				patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
				*patchedAddress += deltaImageBase;
			}
		}
		relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)Func + deltaImageBase), (LPVOID)GetCurrentProcessId(), 0, NULL);
}

// https://stackoverflow.com/a/14678800
std::string ReplaceString(std::string subject, const std::string& search,
	const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

std::string GetSteamPath()
{
	HKEY key;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", &key);
	char buf[256];
	DWORD size = sizeof(buf) / sizeof(buf[0]);
	RegQueryValueExA(key, "InstallPath", 0, NULL, (BYTE*)buf, &size);
	return std::string(buf);
}

// Assumes the libraryfolders.vdf is "well formed"
std::string GetCSSPath(std::string const & steampath)
{
	std::ifstream libraryfolders(steampath + "\\steamapps\\libraryfolders.vdf");
	std::string line, css_path, library_path;
	while (std::getline(libraryfolders, line))
	{
#define PPPPP "\t\t\"path\"\t\t\""
		if (line.rfind(PPPPP, 0) == 0)
		{
			library_path = line.substr(sizeof(PPPPP) - 1, line.size() - sizeof(PPPPP));
			library_path = ReplaceString(library_path, "\\\\", "\\");
		}

		if (line.rfind("\t\t\t\"4000\"", 0) == 0)
		{
			css_path = library_path;
			break;
		}
	}
	if (css_path != "")
		css_path += "\\steamapps\\common\\GarrysMod\\";
	return css_path;
}

std::string GetSteamID3()
{
	HKEY key;
	RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Valve\\Steam\\ActiveProcess", &key);
	DWORD steamid3, size = sizeof(steamid3);
	RegQueryValueExA(key, "ActiveUser", 0, NULL, (BYTE*)&steamid3, &size);
	return std::to_string(steamid3);
}

// Assumes "X:\Program Files (x86)\Steam\userdata\STEAMIDHERE\config\localconfig.vdf" is "well formed"
std::string GetCSSLaunchOptions(std::string const & steampath, std::string const & steamid3)
{
	std::ifstream localconfig(steampath + "\\userdata\\" + steamid3 + "\\config\\localconfig.vdf");
	std::string line;
	bool in_css = false;
	while (std::getline(localconfig, line))
	{
		if (line.rfind("\t\t\t\t\t\"4000\"", 0) == 0)
			in_css = true;
		if (line.rfind("\t\t\t\t\t}", 0) == 0)
			in_css = false;
#define LLLLL "\t\t\t\t\t\t\"LaunchOptions\"\t\t\""
		if (in_css && line.rfind(LLLLL, 0) == 0)
		{
			line = line.substr(sizeof(LLLLL) - 1, line.size() - sizeof(LLLLL));
			line = ReplaceString(line, "\\\\", "\\");
			return line;
		}
#if 0
		// You're not going to believe it but this section is required to not crash when spawning in.
		for (int i = 0; i < 5; i++)
			(void)GetCurrentProcessId();
#endif
	}
	return "";
}

//Сredits: https://github.com/alkatrazbhop/BunnyhopAPE
int main()
{
	SetConsoleTitle("RawInput2BunnyhopAPE x64");
	printf("https://github.com/rtldg/RawInput2BunnyhopAPE\n\n");

	//printf("%d\n", &(((struct request_t*)0)->total));

	auto steamid3 = GetSteamID3();
	printf("steamid3  = %s\n", steamid3.c_str());
	auto steam_path = GetSteamPath();
	printf("steampath = %s\n", steam_path.c_str());
	auto launch_options = GetCSSLaunchOptions(steam_path, steamid3);
	launch_options = "-insecure -novid -console   " + launch_options;
	printf("launchopt = %s\n", launch_options.c_str());
	auto css_path = GetCSSPath(steam_path);
	printf("css path  = %s\n\n", css_path.c_str());
	auto css_exe = css_path + "bin\\win64\\gmod.exe";

	PROCESS_INFORMATION pi = {};
	STARTUPINFOA si = {};

	if (!CreateProcessA(css_exe.c_str(), (char*)launch_options.c_str(), NULL, NULL, FALSE, 0, NULL, css_path.c_str(), &si, &pi))
	{
		auto err = GetLastError();
		char* buf;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);

		printf("CreateProcessA failed (0x%x): %s\n", err, buf);

		while (1)
		{
			if (_kbhit() && _getch() == VK_RETURN)
				return 0;
			Sleep(500);
		}

		return 1;
	}


	while (1)
	{
		auto pClient = GetModuleHandleExtern(pi.dwProcessId, "client.dll");
		if (pClient) break;
		Sleep(1000);
		DWORD exitcode;
		if (GetExitCodeProcess(pi.hProcess, &exitcode) && exitcode != STILL_ACTIVE)
			return 0;
	}

	//system("cls");
	printf("Set \"m_rawinput 2\" in game for it to take effect\n");

	PEInjector(pi.hProcess, InjectionEntryPoint);

	WaitForSingleObject(pi.hProcess, INFINITE);
	return 0;
}
