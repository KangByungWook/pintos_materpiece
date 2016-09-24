#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h>
#include <threads/thread.h>
#include <filesys/filesys.h>
#include <"userprog/process.h">
#include <threads/synch.h>
static void syscall_handler (struct intr_frame *f UNUSED);
void check_address(void *addr);
void check_address22(void *addr);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
tid_t exec(const char *cmd_line);
int wait(tid_t tid);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
  int *arg;
  uint32_t *sp=f->esp;
  check_address((void*)sp);
  int syscall_num =*sp;

  //thread_exit ();
  switch(syscall_num){
	case SYS_HALT:
	  halt();
	  break;
	case SYS_EXIT:
	  arg=(int*)malloc(sizeof(int)); 
	  get_argument(f->esp,arg,1);
	  exit((int)arg[0]);
	  break;
	case SYS_EXEC:
	  arg=(int*)malloc(sizeof(int));
  	  get_argument(f->esp,arg,1);
	  check_address((void*)arg[0]);
	  f->eax=exec((const char*)arg[0]);
          break;
	case SYS_WAIT:
	  arg=(int*)malloc(sizeof(int));
  	  get_argument(f->esp,arg,1);
	  f->eax=wait((tid_t)arg[0]); 
	  break;
	case SYS_CREATE:
	  arg=(int*)malloc(sizeof(int)*2);
          get_argument(f->esp,arg,2);
	  check_address((void*)arg[0]);
	  f->eax=create((const char*)arg[0],(unsigned)arg[1]);
	  break;
   	case SYS_REMOVE:
	  arg=(int*)malloc(sizeof(int));
          get_argument(f->esp,arg,1);
          check_address((void*)arg[0]);
          f->eax=remove((const char*)arg[0]);
          break;
 	case SYS_OPEN:
	  arg=(int*)malloc(sizeof(int));
          get_argument(f->esp,arg,1);
          check_address((void*)arg[0]);
	  f->eax=open((const char*)arg[0]);
	  break; 
	case SYS_FILESIZE:
	  arg=(int*)malloc(sizeof(int));
          get_argument(f->esp,arg,1);
          f->eax=filesize((int)arg[0]);
	  break;
	case SYS_READ:
	  arg=(int*)malloc(sizeof(int)*3);
          get_argument(f->esp,arg,3);
          check_address((void*)arg[1]);
	  f->eax=read((int)arg[0],(void*)arg[1],(unsigned)arg[2]);
	  break;
	case SYS_WRITE:
	  arg=(int*)malloc(sizeof(int)*3);
          get_argument(f->esp,arg,3);
          check_address((void*)arg[1]);
	  f->eax=write((int)arg[0],(void*)arg[1],(unsigned)arg[2]);
	  break;
	case SYS_SEEK:
	  arg=(int*)malloc(sizeof(int)*2);
          get_argument(f->esp,arg,2);
	  seek((int)arg[0],(unsigned)arg[1]);
	  break;
	case SYS_TELL:
	  arg=(int*)malloc(sizeof(int));
          get_argument(f->esp,arg,1);
          f->eax=tell((int)arg[0]);
	  break;
	case SYS_CLOSE:
	  arg=(int*)malloc(sizeof(int));
          get_argument(f->esp,arg,1);
          close((int)arg[0]);
	  break;
	
  }
  free(arg);
}
void check_address(void *addr){
  if( addr < 0x08048000 || addr > 0xc0000000)
	exit(-1);
}	
void check_address2(void *addr){
  check_address(addr);
  check_address(addr+3);
}

void get_argument(void *esp, int *arg, int count){
  int i;
  for(i=1;i<=count;i++){
	check_address2((int*)esp+i);
	arg[i-1]=*((int*)esp+i);
  }
}
void halt(void){
  shutdown_power_off();
}
void exit(int status){
   thread_current()->exit_status=status;
   printf("%s: exit(%d)\n",thread_name(), status);
   thread_exit();
}

bool create(const char *file, unsigned initial_size){
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  return filesys_remove(file);
}
tid_t exec(const char *cmd_line){
  tid_t temp;
  struct thread *get_child;
  temp = process_execute(cmd_line);
  if (temp == TID_ERROR) return TID_ERROR;
  get_child = get_child_process(temp);
  if (get_child->load_check == -1)sema_down(&get_child->load);
  if (get_child->load_check == 0)return TID_ERROR;
  return temp;
}
int wait(tid_t tid){
  return  process_wait(tid);
}
int open(const char *file){
	int result=-1;
        if (NULL == file) return -1;
	result=process_add_file(filesys_open(file)); //file == NULL return -1;	
	return result;
}
int filesize(int fd){
	struct file *temp;
	temp = process_get_file(fd);
	if(temp==NULL) return -1;
	return file_length(temp);
}
int read(int fd, void *buffer, unsigned size){
	lock_acquire(&filesys_lock);
        struct file *temp=process_get_file(fd);
	unsigned size_buffer;
	if(fd==0){
	size_buffer=size;
		while(size_buffer--){
			*((char*)buffer)=input_getc();
			buffer++;
		}
	lock_release(&filesys_lock);
	return size;
	}
	else if (temp==NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	else {
	size = file_read(temp,buffer,size);
	lock_release(&filesys_lock);
	return size;
	}
}
int write(int fd, void *buffer, unsigned size){
	lock_acquire(&filesys_lock);
        struct file *temp=process_get_file(fd);
        if(fd==1){
        	putbuf(buffer,size);
       		lock_release(&filesys_lock);
       		return size;
        }
        else if (temp==NULL) {
                lock_release(&filesys_lock);
                return -1;
        }
        else {
        size = file_write(temp,buffer,size);
        lock_release(&filesys_lock);
        return size;
 	}
}
void seek(int fd, unsigned position){
	struct file *temp = process_get_file(fd);
	if(temp==NULL) return ;
	file_seek(temp,position);
}
unsigned tell(int fd){
	struct file *temp = process_get_file(fd);
	if(temp==NULL) return -1;
	return file_tell(temp);
}
void close(int fd){
	process_close_file(fd);
}

