import pefile
import sys

def main():
    try:
        pe = pefile.PE("shellcode.exe")
    except FileNotFoundError:
        print("[-] Error: shellcode.exe not found. Build it first.")
        return
    # 查找代码段 (.text)
    section_found = False
    for section in pe.sections:
        if b".text" in section.Name:
            shellcode = section.get_data()
            shellcode = shellcode.rstrip(b'\x00') 
            print(f"// Extracted Shellcode Size: {len(shellcode)} bytes")
            print("unsigned char shellcode[] = {")
            out = ""
            for i, byte in enumerate(shellcode):
                out += f"0x{byte:02X}, "
                if (i + 1) % 16 == 0:
                    print(f"    {out}")
                    out = ""
            if out:
                print(f"    {out}")
            print("};")
            section_found = True
            break
    
    if not section_found:
        print("[-] Error: .text section not found in exe.")

if __name__ == "__main__":
    main()