; ProxyApiStubs.asm

.code

;================================================
; StubProxyNtCreateThreadEx Procedure
;================================================
StubProxyNtCreateThreadEx PROC
	
	push rsi					; Backup rsi registers value
	mov rsi, rcx				; Backup CreateThreadCtx structure into a non volatile register

	mov rax, [rsi]				; Move NtCreateThreadEx into rax
	
	; ======= REGISTER PARAMETERS (RCX, RDX, R8, R9) ======
	mov rcx, [rsi + 8h]			; Move ThreadHandle parameter into rcx
	mov rdx, 1FFFFFh			; Move THREAD_ALL_ACCESS into rdx
	xor r8, r8					; ObjectAttributes = 0
	mov r9, [rsi + 10h]			; Move ProcessHandle parameter into r9

	; ====== STACK PARAMETERS ======
	mov r10, [rsi + 18h]		; Move StartRoutine parameter into r10
	mov [rsp + 30h], r10		; Arguments beyond 4 are pushed onto the stack

	mov r11, [rsi + 20h]		; Move Argument parameter into r11
	mov [rsp + 38h], r11		; Push onto the stack

	xor r11, r11				; Zero out the r11 register
	mov [rsp + 40h], r11		; CreateFlags = 0
	mov [rsp + 48h], r11		; ZeroBits = 0
	mov [rsp + 50h], r11		; StackSize = 0
	mov [rsp + 58h], r11		; MaximumStackSize = 0
	mov [rsp + 60h], r11		; AttributeList = 0

	pop rsi						; Restore original RSI value
	jmp rax						; Jump directly to the NtCreateThreadEx

StubProxyNtCreateThreadEx ENDP

;================================================
; StubProxyNtProtectVirtualMemory Procedure
;================================================
StubProxyNtProtectVirtualMemory PROC
	
	push rdi					; Backup rdi registers value
	mov rdi, rcx				; Backup ProtectMemoryCtx structure into a non volatile register
	
	mov rax, [rdi]				; Move NtProtectVirtualMemory into rax

	; ======= REGISTER PARAMETERS (RCX, RDX, R8, R9) ======
	mov rcx, [rdi + 8h]			; Move ProcessHandle parameter into rcx
	mov rdx, [rdi + 10h]		; Move *BaseAddress parameter into rdx
	mov r8, [rdi + 18h]			; Move RegionSize parameter into r8
	mov r9, [rdi + 20h]			; Move NewProtection parameter into r9

	; ====== STACK PARAMETERS ======
	mov r10, [rdi + 28h]		; Move OldProtection parameter into r10
	mov [rsp + 30h], r10		; Push onto the stack

	pop rdi						; Restore original RDI value
	jmp rax						; Jump directly to the NtProtectVirtualMemory

StubProxyNtProtectVirtualMemory ENDP

END