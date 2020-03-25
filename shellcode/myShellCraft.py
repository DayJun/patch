opcode = {"jmp_offset": '\xE9', 'call_offset': '\xe8'}
shellcode64 = {
     'readLog': """
          push rdi
          push rsi
          push rdx
          lea rsi, [rsp-0x1000]
          mov rax, 0
          syscall
          push rax
          lea rdi, [rip]
          and rdi, 0xfffffffffffff000
          sub rdi, {0}
          add rdi, {1}
          mov rsi, 0x441
          mov rax, 2
          mov rdx, 0x1b6
          syscall
          push rax
          cmp rax, -1
          jz fail
          mov rdi, rax
          mov rsi, [rsp+0x8]
          shl rsi, 40
          mov rax, 0x3a64616572
          add rsi, rax
          push rsi
          mov rsi, rsp
          mov rdx, 6
          mov rax, 1
          syscall
          add rsp, 8
          mov rdi, [rsp]
          lea rsi, [rsp+0x28]
          mov rdx, 8
          mov rax, 1
          syscall
          mov rdi, [rsp]
          lea rsi, [rsp-0xff0]
          mov rdx, qword ptr [rsp+0x8]
          mov rax, 1
          syscall
          pop rdi
          mov rax, 3
          syscall
          pop rcx
          mov rax, rcx
          pop rsi
          pop rsi
          lea rdi, [rsp-0x1010]
     trans:
          dec rcx
          mov bl, byte ptr [rdi+rcx]
          mov byte ptr [rsi+rcx], bl
          test rcx, rcx
          jz finish
          jmp trans
     fail:
          mov rax, 60
          syscall
     finish:
          add rsp, 8
          ret
          """, 


     '__isoc99_scanfLog':"""
          push rdi
          push rsi
          lea rdi, [rip]
          and rdi, 0xfffffffffffff000
          sub rdi, {0}
          add rdi, {1}
          mov rsi, 0x441
          mov rax, 2
          mov rdx, 0x1b6
          syscall
          push rax
          cmp rax, -1
          jz fail
          mov rdi, 0x3a666e616373
          push rdi
          lea rsi, [rsp]
          mov rdi, rax
          mov rdx, 6
          mov rax, 1
          syscall
          mov rdi, qword ptr [rsp+8]
          mov rsi, qword ptr [rsp+0x18]
          mov rax, 1
          mov rdx, 1
     write:
          syscall
          cmp byte ptr [rsi], 0
          jz done
          inc rsi
          jmp write
     fail:
          mov rax, 60
          syscall
     done:
          syscall
          lea rsi, [rsp+0x20]
          mov rdx, 8
          syscall
          mov rax, 3
          syscall
          add rsp, 0x10
          pop rsi
          pop rdi
          nop
          nop
          nop
          nop
          nop
     """
        }
init_shellcode64 = {
     'initLog':  """
          push rax
          push rbx
          push rcx
          push rdx
          push rdi
          push rsi
          push r8
          push r9
          push r10
          push r11
          push r12
          push r13
          push r14
          push r15
          push rbp
          pushf
          lea rdi, [rip]
          and rdi, 0xfffffffffffff000
          push rdi
          mov rdi, 0x6d6f646e
          push rdi
          mov rdi, 0x6172752f7665642f
          push rdi
          mov rdi, rsp
          mov rsi, 0
          mov rax, 2
          syscall
          mov rdi, rax
          cmp rax, -1
          jz fail
          pop rsi
          pop rsi
          pop rsi
          sub rsi, {0}
          add rsi, {1}
          push rsi
          mov rdx, 4
          mov rax, 0
          syscall
          mov rax, 3
          mov rdi, 3
          syscall
          pop rsi
          lea rdi, [rsi+8]
          mov rcx, 4
          xor rdx, rdx
          mov byte ptr[rdi+rdx], 0x2f
          inc rdx
          mov byte ptr[rdi+rdx], 0x74
          inc rdx
          mov byte ptr[rdi+rdx], 0x6d
          inc rdx
          mov byte ptr[rdi+rdx], 0x70
          inc rdx
          mov byte ptr[rdi+rdx], 0x2f
          inc rdx
     trans:
          dec rcx
          mov bl, byte ptr[rsi+rcx]
          mov al, bl
          and bl, 0xf
          and al, 0xf0
          shr al, 4
          cmp al, 0xa
          js anum
          jmp aalpha
     fail:
          mov rax, 60
          syscall
     anum: 
          add al, 48
          jmp b
     aalpha:
          add al, 87
          jmp b
     b:
          cmp bl, 0xa
          js bnum
          jmp balpha
     bnum: 
          add bl, 48
          jmp save
     balpha:
          add bl, 87
     save:
          mov byte ptr[rdi+rdx], al
          inc rdx
          mov byte ptr[rdi+rdx], bl
          inc rdx
          test rcx, rcx
          jnz trans
     end:
          mov byte ptr[rdi+rdx], 0x2e
          inc rdx
          mov byte ptr[rdi+rdx], 0x70
          inc rdx
          mov byte ptr[rdi+rdx], 0x77
          inc rdx
          mov byte ptr[rdi+rdx], 0x6e
          inc rdx
          mov byte ptr[rdi+rdx], 0x6c
          inc rdx
          mov byte ptr[rdi+rdx], 0x6f
          inc rdx
          mov byte ptr[rdi+rdx], 0x67
          inc rdx
          popf
          pop rbp
          pop r15
          pop r14
          pop r13
          pop r12
          pop r11
          pop r10
          pop r9
          pop r8
          pop rsi
          pop rdi
          pop rdx
          pop rcx
          pop rbx
          pop rax
          nop
          nop
          nop
          nop
          nop
     """
          }

shellcode32 = {
     'readLog': """
          pusha
          pushf
          mov ebx, dword ptr [esp+0x28]
          lea ecx, [esp-0x1000]
          mov edx, dword ptr [esp+0x30]
          mov eax, 3
          int 0x80
          push eax
          call openfile
     openfile:
          mov ebx, [esp]
          and ebx, 0xfffff000
          sub ebx, {0}
          add ebx, {1}
          mov ecx, 0x441
          mov edx, 0x1b6
          mov eax, 5
          int 0x80
          mov ebx, eax
          push eax
          cmp eax, -1
          jz fail
          mov ebx, eax
          mov ecx, [esp+8]
          shl ecx, 8
          mov esi, 0x3a
          add esi, ecx
          push esi
          mov esi, 0x64616572
          push esi
          mov ecx, esp
          mov edx, 6
          mov eax, 4
          int 0x80
          mov ebx, [esp+8]
          lea ecx, [esp+0x38]
          mov edx, 4
          mov eax, 4
          int 0x80
          lea ecx, [esp-0xfec]
          mov edx, [esp+0x10]
          mov eax, 4
          int 0x80
          mov ebx, [esp+8]
          mov eax, 6
          int 0x80
          mov ecx, [esp+0x10]
     trans:
          dec ecx
          mov edi, dword ptr [esp+0x40]
          lea esi, [esp-0xfec]
          mov bl, byte ptr [esi+ecx]
          mov byte ptr [edi+ecx], bl
          test ecx, ecx
          jnz trans
          add esp, 0x14
          popf
          popa
          ret
     fail:
          mov eax, 1
          int 0x80
          """,


     '__isoc99_scanfLog':"""
          pusha
          pushf
          call openfile
     openfile:
          mov ebx, [esp]
          and ebx, 0xfffff000
          sub ebx, {0}
          add ebx, {1}
          mov ecx, 0x441
          mov edx, 0x1b6
          mov eax, 5
          int 0x80
          push eax
          cmp eax, -1
          jz fail
          mov edi, 0x3a66
          push edi
          mov edi, 0x6e616373
          push edi
          lea ecx, [esp]
          mov ebx, dword ptr[esp+8]
          mov edx, 6
          mov eax, 4
          int 0x80
          mov ebx, dword ptr [esp+8]
          mov ecx, dword ptr [esp+0x14]
          mov eax, 4
          mov edx, 1
     write:
          int 0x80
          cmp byte ptr [ecx], 0
          jz done
          inc ecx
          mov eax, 4
          jmp write
     fail:
          mov eax, 1
          int 0x80
     done:
          mov eax, 4
          int 0x80
          mov eax, 4
          mov edx, 4
          lea ecx, [esp+0x10]
          int 0x80
          mov eax, 6
          int 0x80
          add esp, 0x10
          popf
          popa
          nop
          nop
          nop
          nop
          nop
     """
        }
init_shellcode32 = {
     'initLog':  """
          pusha
          pushf
          push 0
          mov edi, 0x6d6f646e
          push edi
          mov edi, 0x6172752f
          push edi
          mov edi, 0x7665642f
          push edi
          mov ebx, esp
          xor ecx, ecx
          xor edx, edx
          mov eax, 5
          int 0x80
          call tmp
     tmp:
          mov ebx, eax
          mov ecx, dword ptr[esp]
          add esp, 4
          and ecx, 0xfffff000
          sub ecx, {0}
          add ecx, {1}
          mov edx, 4
          mov eax, 3
          int 0x80
          mov eax, 6
          mov ebx, 3
          int 0x80
          mov esi, ecx
          lea edi, [esi+8]
          mov ecx, 4
          xor edx, edx
          mov byte ptr[edi+edx], 0x2f
          inc edx
          mov byte ptr[edi+edx], 0x74
          inc edx
          mov byte ptr[edi+edx], 0x6d
          inc edx
          mov byte ptr[edi+edx], 0x70
          inc edx
          mov byte ptr[edi+edx], 0x2f
          inc edx

          trans:
          dec ecx
          mov bl, byte ptr[esi+ecx]
          mov al, bl
          and bl, 0xf
          and al, 0xf0
          shr al, 4
          cmp al, 0xa
          js anum
          jmp aalpha
     fail:
          mov eax, 60
          syscall
     anum: 
          add al, 48
          jmp b
     aalpha:
          add al, 87
          jmp b
     b:
          cmp bl, 0xa
          js bnum
          jmp balpha
     bnum: 
          add bl, 48
          jmp save
     balpha:
          add bl, 87
     save:
          mov byte ptr[edi+edx], al
          inc edx
          mov byte ptr[edi+edx], bl
          inc edx
          test ecx, ecx
          jnz trans
     end:
          mov byte ptr[edi+edx], 0x2e
          inc edx
          mov byte ptr[edi+edx], 0x70
          inc edx
          mov byte ptr[edi+edx], 0x77
          inc edx
          mov byte ptr[edi+edx], 0x6e
          inc edx
          mov byte ptr[edi+edx], 0x6c
          inc edx
          mov byte ptr[edi+edx], 0x6f
          inc edx
          mov byte ptr[edi+edx], 0x67
          inc edx
          add esp, 0x10
          popf
          popa
          nop
          nop
          nop
          nop
          nop
     """
          }