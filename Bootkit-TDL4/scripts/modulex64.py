# 
# SELF IMPORTANT NOTE:
# 	Welcome to Windows 7 64-bit Boot Debugging ! ! ! 
# 	Use this script on the Ntoskrnl Entry Point
# 	where rcx is the KeLoaderBlock

import idaapi

# get the address of LoadOrderListHead structure
def get_LoadOrderListHead():
  KeLoaderBlock = int(GetRegValue("RCX"))
  LoadOrderListHead = KeLoaderBlock + 0x10
  return LoadOrderListHead

#read a string from UNICODE_STRING structure
def get_unistr(addr):
  #print "%016X"%addr
  len = Word(addr)        #USHORT Length;
  start = Qword(addr+0x8) #PWSTR  Buffer;
  if len>1000:
    raise Exception("%08X: String too long (%d)"%(addr, len))
  res = u''
  while len>0:
    c = Word(start)
    if c==0: break
    res += unichr(c)
    start += 2
    len -= 1
  return res
  
#self note
# at this point windows is still booting up, some of these modules will be relocated to an address
# so i will not do any memory mapping (creating segments) yet of these modules. 
def walk_modulelist(list):
  # get the first module
  cur_mod = Qword(list)
  # loop until we come back to the beginning
  while cur_mod != list and cur_mod != BADADDR:
    #print "%08X"%cur_mod
    BaseAddress  = Qword(cur_mod+0x30)
    EntryPoint   = Qword(cur_mod+0x38)
    SizeOfImage  = Qword(cur_mod+0x40)
    FullDllName  = get_unistr(cur_mod+0x48).encode('utf-8')
    BaseDllName  = get_unistr(cur_mod+0x58).encode('utf-8')

    print "Module: {0} - BaseAddress: 0x{1:X} - EntryPoint: 0x{2:X} - FullDllName: {3}".format(BaseDllName,BaseAddress,EntryPoint,FullDllName)

    #get next module (FLink)
    next_mod = Qword(cur_mod)
    #check that BLink points to the previous structure
    if Qword(next_mod+0x8)!=cur_mod:
      print "%08X: List error!"%cur_mod
      break
    cur_mod = next_mod

def walk_bootdriverlist():
	BootDriverList = int(GetRegValue("RCX")) + 0x30
  # get the first module
	cur_entry = Qword(BootDriverList)
  # loop until we come back to the beginning
	while cur_entry != BootDriverList and cur_entry != BADADDR:
		
		FilePath = get_unistr(cur_entry+0x10).encode('utf-8')
		RegistryPath = get_unistr(cur_entry+0x20).encode('utf-8')
		PLdrEntry = Qword(cur_entry+0x30)
    
		print "PLdrEntry: 0x{0:X} - FilePath: {1} - RegistryPath: {2}".format(PLdrEntry,FilePath,RegistryPath)
    
    #get next module (FLink)
		next_entry = Qword(cur_entry)
    #check that BLink points to the previous structure
		if Qword(next_entry+0x8)!=cur_entry:
			print "%08X: List error!"%cur_entry
			break
		cur_entry = next_entry
	

list = get_LoadOrderListHead()
if list:
	#walk_bootdriverlist()
	walk_modulelist(list) 
