#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <TlHelp32.h>
#include <vector>
#include"LDasm.h"

typedef DWORD64 qw;



extern "C" void node();
extern "C" void int3();

extern "C" int printLn(const char* text);
extern "C" int msg(const char* text);

int msg(const char* text)
{
    return MessageBoxA(0, text, 0, 0);
}

int printLn(const char* text)
{
    return printf("%s \n",text);
}

// 读取原始指令并计算长度
size_t getOriginalInstructionLength(DWORD_PTR address,int size) {

    void* buffer=VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //char* buffer = new char[size];
    //char buffer[32];

    memcpy(buffer,(void*)address,size);

    size_t totalLength = 0;

    ldasm_data ld = { 0 };

    totalLength = ldasm(buffer, &ld, true);

    while (1)
    {
        if (totalLength < size)
        {
            totalLength+= ldasm((void*)((DWORD64)buffer+ totalLength), &ld, true);
            std::cout << totalLength << std::endl;
        }
        else
        {
            break;
        }
    }

    //delete[] buffer;
    VirtualFree(buffer, size, MEM_RELEASE);
    return totalLength;
}





// Adjusts the relative offset for RIP-relative instructions
int32_t AdjustRIPRelativeOffset(uintptr_t instruction_address, int32_t original_offset, uintptr_t old_base, uintptr_t new_base) {
    // Calculate the original target address in the new module
    uintptr_t original_target = instruction_address + original_offset + 4;  // 4 is the size of the offset field
    // Calculate the corresponding target address in the old module
    uintptr_t new_target = old_base + (original_target - new_base);

    // Calculate the new offset relative to the instruction's address
    return static_cast<int32_t>(new_target - instruction_address - 4);// 4在此处未起到作用


    //新的指令偏移 = 老的指令偏移 + 老地址 - 新地址
    //    例如，
    //    0000000000401096 | E8 85000000 | call 0x0000000000401120 |

    //    401096 + 85 - 4010D0 = 4B
}

// Function to fix RIP-relative addressing instructions
void FixRIPRelativeInstructions(uintptr_t old_base, uintptr_t new_base, uintptr_t start_address, size_t size) {
    for (uintptr_t addr = start_address; addr < start_address + size; ) {
        uint8_t* instruction = reinterpret_cast<uint8_t*>(addr);

        // Match different RIP-relative instructions
        if ((instruction[0] == 0x48 && instruction[1] == 0x8D && instruction[2] == 0x15) ||  // LEA rdx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8D && instruction[2] == 0x0D) ||  // LEA rcx, [RIP + offset]

            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x2D) ||  // MOV rbp, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x25) ||  // MOV rsp, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x35) ||  // MOV rsi, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x3D) ||  // MOV rdi, [RIP + offset]

            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x05) ||  // CMP r8, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x0D) ||  // CMP r9, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x15) ||  // CMP r10, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x1D) ||  // CMP r11, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x25) ||  // CMP r12, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x2D) ||  // CMP r13, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x35) ||  // CMP r14, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x3B && instruction[2] == 0x3D) ||  // CMP r15, [RIP + offset]

            (instruction[0] == 0x48 && instruction[1] == 0x3B && instruction[2] == 0x0D) ||  // CMP rcx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x3B && instruction[2] == 0x15) ||  // CMP rdx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x3B && instruction[2] == 0x1D) ||  // CMP rbx, [RIP + offset]


            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x05) ||  // MOV r8, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x0D) ||  // MOV r9, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x15) ||  // MOV r10, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x1D) ||  // MOV r11, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x25) ||  // MOV r12, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x2D) ||  // MOV r13, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x35) ||  // MOV r14, [RIP + offset]
            (instruction[0] == 0x4C && instruction[1] == 0x8B && instruction[2] == 0x3D) ||  // MOV r15, [RIP + offset]


            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x0D) ||  // MOV rcx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x15) ||  // MOV rdx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x1D) ||  // MOV rbx, [RIP + offset]
            (instruction[0] == 0x48 && instruction[1] == 0x8B && instruction[2] == 0x05)) {  // MOV rax, [RIP + offset]

            int32_t* offset_field = reinterpret_cast<int32_t*>(addr + 3);

            // Calculate the new offset to point to the old module
            int32_t new_offset = AdjustRIPRelativeOffset(addr, *offset_field, old_base, new_base);

            // Update the instruction with the new offset
            *offset_field = new_offset;

            std::cout << "Updated RIP-relative instruction at " << std::hex << addr
                << " with new offset " << std::hex << new_offset << std::endl;

            // Move to the next instruction (LEA/MOV is 7 bytes long)
            addr += 7;
        }
        else if (instruction[0] == 0xFF && instruction[1] == 0x15 || //call [RIP + offset]
            instruction[0] == 0xFF ||
            instruction[1] == 0x25) {  // jmp [RIP + offset]

            int32_t* offset_field = reinterpret_cast<int32_t*>(addr + 2);

            // Calculate the new offset to point to the old module
            int32_t new_offset = AdjustRIPRelativeOffset(addr, *offset_field, old_base, new_base);

            // Update the instruction with the new offset
            *offset_field = new_offset;

            std::cout << "Updated RIP-relative CALL/JMP at " << std::hex << addr
                << " with new offset " << std::hex << new_offset << std::endl;

            // Move to the next instruction (CALL/JMP is 5 bytes long)
            addr += 6;
        }
        else if (instruction[0] == 0xE8 || instruction[0] == 0xE9) {  // CALL/JMP rel32
            int32_t* offset_field = reinterpret_cast<int32_t*>(addr + 1);

            // Calculate the new offset to point to the old module
            int32_t new_offset = AdjustRIPRelativeOffset(addr, *offset_field, old_base, new_base);

            // Update the instruction with the new offset
            *offset_field = new_offset;

            std::cout << "Updated RIP-relative CALL/JMP at " << std::hex << addr
                << " with new offset " << std::hex << new_offset << std::endl;

            // Move to the next instruction (CALL/JMP is 5 bytes long)
            addr += 5;
        }
        else {
            // If it's not a known RIP-relative instruction, skip to the next byte
            ++addr;
        }
    }
}

// 填充 NOP 指令
void FillNops(BYTE* address, SIZE_T size) {
    DWORD oldProtect;
    VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect);

    for (SIZE_T i = 0; i < size; ++i) {
        address[i] = 0x90;  // NOP 指令
    }

    VirtualProtect(address, size, oldProtect, &oldProtect);
}




void FixAddressOffset(uintptr_t old_base, uintptr_t new_base)
{

    uintptr_t text_section_start= new_base;
    size_t text_section_size=35;


    if (text_section_start != 0 && text_section_size > 0) {
        FixRIPRelativeInstructions(old_base, new_base, text_section_start, text_section_size);
    }
    else {
        std::cerr << "Data section not found!" << std::endl;
    }
}



extern "C" byte* cpy_entry = NULL; // 原来的代码


void AllocOri2(uint64_t* absoluteAddress,size_t remainingBytes)//拷贝一小块内存
{
    // 在当前进程中分配新的内存,建议是4的倍数
    cpy_entry = (byte*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (cpy_entry == NULL) {
        return ;
    }

    int offset = 32 + remainingBytes;

    // 直接从当前进程读取模块镜像,不需要VirtualProtect修改可读
    memcpy(cpy_entry, (void*)0x004010D0, 32+ remainingBytes);


    FixAddressOffset((uintptr_t)0x004010D0, (uintptr_t)cpy_entry);

    // 插入跳转指令
    //从cpy_entry[35]开始计算

    cpy_entry[offset+0] = 0x48; // mov rax, [targetFunction + hookSize]
    cpy_entry[offset+1] = 0xB8;
    *reinterpret_cast<uintptr_t*>(&cpy_entry[offset+2]) = (uintptr_t)absoluteAddress + 22;//push rax & jmp rax
    cpy_entry[offset + 10] = 0xFF; // jmp rax
    cpy_entry[offset + 11] = 0xE0;
}


qw rax = NULL;

// 写入 mov qword ptr [address], rax 的函数
void push_rax(uint8_t* targetAddress, uint64_t *absoluteAddress) {
    DWORD oldProtect;
    // 修改页面保护属性，允许写入
    VirtualProtect(targetAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 写入机器码
    targetAddress[0] = 0x48; // REX.W 前缀
    targetAddress[1] = 0xA3; // MOV [address], RAX 操作码

    // 写入64位绝对地址
    memcpy(&targetAddress[2], &absoluteAddress, sizeof(uint64_t));

    // 恢复页面保护属性
    VirtualProtect(targetAddress, 10, oldProtect, &oldProtect);
}

// 写入 mov  rax ,qword ptr [address]的函数
void pop_rax(uint8_t* targetAddress, uint64_t* absoluteAddress) {
    DWORD oldProtect;
    // 修改页面保护属性，允许写入
    VirtualProtect(targetAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 写入机器码
    targetAddress[0] = 0x48; // REX.W 前缀
    targetAddress[1] = 0xA1; // MOV  RAX,[address]操作码

    // 写入64位绝对地址
    memcpy(&targetAddress[2], &absoluteAddress, sizeof(uint64_t));

    // 恢复页面保护属性
    VirtualProtect(targetAddress, 10, oldProtect, &oldProtect);
}



void InstallHook(size_t remainingBytes) {// 改变寄存器


    //AllocOri((uint64_t*)0x004010D0);
    AllocOri2((uint64_t*)0x004010D0,remainingBytes);

    push_rax((uint8_t*)0x004010D0, &rax);//10 bytes


    // 找到目标函数地址（示例地址，需要替换为实际地址）
    uintptr_t targetFunctionAddress = 0x004010D0 + 10; // 替换为实际地址

    // 计算需要修改的指令大小
    const size_t hookSize = 12; // 修改的指令字节数
    BYTE* targetFunction = (BYTE*)targetFunctionAddress;

    // 保护内存页面
    DWORD oldProtect;
    VirtualProtect(targetFunction, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect);


    // 插入跳转指令
    targetFunction[0] = 0x48; // mov rax, [targetFunction + hookSize]
    targetFunction[1] = 0xB8;
    *reinterpret_cast<uintptr_t*>(&targetFunction[2]) = (uintptr_t)node;
    targetFunction[10] = 0xFF; // jmp rax
    targetFunction[11] = 0xE0;

    // 恢复原来的保护状态
    VirtualProtect(targetFunction, hookSize, oldProtect, &oldProtect);

    pop_rax((uint8_t*)0x004010D0 + 10 + 12, &rax);//10 bytes

    FillNops((byte*)0x004010D0 + 10 + 12 + 10, remainingBytes); //size=尾地址-首地址=35
}


#define HOOK_JUMP_LEN 14
void* hook_func = NULL; // 被Hook函数的地址
char hook_jump[HOOK_JUMP_LEN];// 修改函数头部跳转的代码

void InstallHook2()//不改变寄存器
{

    hook_func = (void*)0x004010D0;
    VirtualProtect(hook_func, HOOK_JUMP_LEN, PAGE_EXECUTE_READWRITE, NULL); // 允许函数头部内存可读写

    union
    {
        void* ptr;
        struct
        {
            long low;
            long high;
        };
    } ptr64; // 便于获取指针变量的高4字节和低4字节
    ptr64.ptr = (void*)node;
    hook_jump[0] = 0x68; // push xxx
    *(long*)&hook_jump[1] = ptr64.low; // xxx，即地址的低4字节
    hook_jump[5] = 0xC7;
    hook_jump[6] = 0x44;
    hook_jump[7] = 0x24;
    hook_jump[8] = 0x04; // mov dword [rsp+4], yyy
    *(long*)&hook_jump[9] = ptr64.high; // yyy，即地址的高4字节
    hook_jump[13] = 0xC3; // ret


    WriteProcessMemory(GetCurrentProcess(), hook_func, hook_jump, HOOK_JUMP_LEN, NULL);

    FillNops((byte*)0x004010D0 + 14, 4);
}


void Run()
{

    const DWORD_PTR address = 0x004010D0;  // 要 hook 的地址
    const size_t hookSize = 32;             // hook 的字节数


    size_t originalLength[8] = { 0 };


    for (int i = 0; i < 8; i++)
    {
        // 获取原始指令长度
        originalLength[i] = getOriginalInstructionLength(address,32+i);
        std::cout << std::format("Original instruction[{0}] length: ",i) << originalLength[i] << " bytes" << std::endl;

    }

    size_t remainingBytes = 0;

    for (int i = 0; i < 8; i++)
    {
        // 计算剩余未被覆盖的字节数
        remainingBytes = originalLength[i] > hookSize ? originalLength[i] - hookSize : 0;

        if (remainingBytes > 0)
        {
            std::cout << "Remaining bytes after hook: " << remainingBytes << " bytes" << std::endl;
            break;
        }

    }


    //int3();
    InstallHook(remainingBytes);
    //InstallHook2();

}


BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Run, nullptr, 0, nullptr);
        //MessageBox(0, 0, 0, 0);
		break;

	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}