
#include <cstring>
#include <cstdlib>
#include <iostream>
#include "platform.h"
#include "ucioption.h"

#define TRUE 1
#define FALSE 0
static int large_use;
static int num;


#ifndef _WIN32 // Linux 
#include <sys/ipc.h>
#include <sys/shm.h>
void SETUP_PRIVILEGES () {}
void CREATE_MEM (void** A, int align, uint64_t size)
{
  large_use = FALSE;

  if (Options["TryLargePages"])
    {
      num = shmget (IPC_PRIVATE, size, IPC_CREAT | SHM_R | SHM_W | SHM_HUGETLB);
      if (num == -1)
	MEMALIGN ((*A), align, size);
      else
	{
	  (*A) = shmat (num, NULL, 0x0);
	  large_use = TRUE;
	  std::cout << "info string HUGELTB " << (size >> 20) << std::endl;
	}
    }
  else
      MEMALIGN ((*A), align, size);
}


void FREE_MEM (void* A)
{
  if (!A)
    return;
  if (!large_use)
    {
      ALIGNED_FREE (A);
      return;
    }
  shmdt (A);
  shmctl (num, IPC_RMID, NULL);
}
#endif


void CREATE_MEM (void** A, int align, uint64_t size)
{
  large_use = FALSE;
  if (Options["TryLargePages"])
    {
      (*A) = VirtualAlloc /* Vlad0 */
	(NULL, size, MEM_LARGE_PAGES|MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
      if ((*A)) /* HACK */
	{
	  large_use = TRUE;
	  std::cout << "info string WindowsLargePages " << (size >> 20) << std::endl;
	}
      else
	  MEMALIGN ((*A), align, size);
    }
  else
      MEMALIGN ((*A), align, size);
}

void FREE_MEM (void* A)
{
  if (!A)
    return;
  if (!large_use)
    {
      ALIGNED_FREE (A);
      return;
    }
  VirtualFree (A, 0, MEM_RELEASE);
}

void SETUP_PRIVILEGES ()
 /* http://msdn.microsoft.com/en-us/library/aa366543%28VS.85%29.aspx */
{
  HANDLE token_handle;
  TOKEN_PRIVILEGES tp;
  OpenProcessToken
    (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle);
  LookupPrivilegeValue (NULL, TEXT ("SeLockMemoryPrivilege"), &tp.Privileges[0].Luid);
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges (token_handle, FALSE, &tp, 0, NULL, 0);
  CloseHandle (token_handle);
}

