package nachos.userprog;

import nachos.machine.*;
import nachos.threads.*;
import nachos.userprog.*;

import java.io.EOFException;

/**
 * Encapsulates the state of a user process that is not contained in its user
 * thread (or threads). This includes its address translation state, a file
 * table, and information about the program being executed.
 * 
 * <p>
 * This class is extended by other classes to support additional functionality
 * (such as additional syscalls).
 * 
 * @see nachos.vm.VMProcess
 * @see nachos.network.NetProcess
 */
public class UserProcess {
	/**
	 * Allocate a new process.
	 */
	public UserProcess() {
		int numPhysPages = Machine.processor().getNumPhysPages();
		pageTable = new TranslationEntry[numPhysPages];
		for (int i = 0; i < numPhysPages; i++)
			pageTable[i] = new TranslationEntry(i, i, true, false, false, false);

		this.PID = uniquePID;
		uniquePID++;

		openFiles = new HashMap<int, Openfile>();
		childProcessMap=new HashMap<Integer, ChildProcess>();
		fdList = new ArrayList<Integer>(Arrays.asList(2,3,4,5,6,7,8,9,10));
		openFiles.put(0, UserKernel.console.openForReading());
		openFiles.put(1, UserKernel.console.openForWriting());

	}

	/**
	 * Allocate and return a new process of the correct class. The class name is
	 * specified by the <tt>nachos.conf</tt> key
	 * <tt>Kernel.processClassName</tt>.
	 * 
	 * @return a new process of the correct class.
	 */
	public static UserProcess newUserProcess() {
		return (UserProcess) Lib.constructObject(Machine.getProcessClassName());
	}

	/**
	 * Execute the specified program with the specified arguments. Attempts to
	 * load the program, and then forks a thread to run it.
	 * 
	 * @param name the name of the file containing the executable.
	 * @param args the arguments to pass to the executable.
	 * @return <tt>true</tt> if the program was successfully executed.
	 */
	public boolean execute(String name, String[] args) {
		if (!load(name, args))
			return false;

		new UThread(this).setName(name).fork();

		return true;
	}

	/**
	 * Save the state of this process in preparation for a context switch.
	 * Called by <tt>UThread.saveState()</tt>.
	 */
	public void saveState() {
	}

	/**
	 * Restore the state of this process after a context switch. Called by
	 * <tt>UThread.restoreState()</tt>.
	 */
	public void restoreState() {
		Machine.processor().setPageTable(pageTable);
	}

	/**
	 * Read a null-terminated string from this process's virtual memory. Read at
	 * most <tt>maxLength + 1</tt> bytes from the specified address, search for
	 * the null terminator, and convert it to a <tt>java.lang.String</tt>,
	 * without including the null terminator. If no null terminator is found,
	 * returns <tt>null</tt>.
	 * 
	 * @param vaddr the starting virtual address of the null-terminated string.
	 * @param maxLength the maximum number of characters in the string, not
	 * including the null terminator.
	 * @return the string read, or <tt>null</tt> if no null terminator was
	 * found.
	 */
	public String readVirtualMemoryString(int vaddr, int maxLength) {
		Lib.assertTrue(maxLength >= 0);

		byte[] bytes = new byte[maxLength + 1];

		int bytesRead = readVirtualMemory(vaddr, bytes);

		for (int length = 0; length < bytesRead; length++) {
			if (bytes[length] == 0)
				return new String(bytes, 0, length);
		}

		return null;
	}

	/**
	 * Transfer data from this process's virtual memory to all of the specified
	 * array. Same as <tt>readVirtualMemory(vaddr, data, 0, data.length)</tt>.
	 * 
	 * @param vaddr the first byte of virtual memory to read.
	 * @param data the array where the data will be stored.
	 * @return the number of bytes successfully transferred.
	 */
	public int readVirtualMemory(int vaddr, byte[] data) {
		return readVirtualMemory(vaddr, data, 0, data.length);
	}

	/**
	 * Transfer data from this process's virtual memory to the specified array.
	 * This method handles address translation details. This method must
	 * <i>not</i> destroy the current process if an error occurs, but instead
	 * should return the number of bytes successfully copied (or zero if no data
	 * could be copied).
	 * 
	 * @param vaddr the first byte of virtual memory to read.
	 * @param data the array where the data will be stored.
	 * @param offset the first byte to write in the array.
	 * @param length the number of bytes to transfer from virtual memory to the
	 * array.
	 * @return the number of bytes successfully transferred.
	 */
	public int readVirtualMemory(int vaddr, byte[] data, int offset, int length) {
		Lib.assertTrue(offset >= 0 && length >= 0
				&& offset + length <= data.length);

		byte[] memory = Machine.processor().getMemory();

		// for now, just assume that virtual addresses equal physical addresses
		if (vaddr < 0 || vaddr >= memory.length)
			return 0;

		int amount = 0;
		while(length>0 && offset<data.length){
			int addressOffset = vaddr %1024;
			int virtualPage = vaddr / 1024;

        	if (virtualPage >= pageTable.length || virtualPage < 0) {
        		break;
        	}
        	TranslationEntry currPTE = pageTable[virtualPage];
        	if(!currPTE.valid) break;
        	currPTE.used=true;

        	int physicalPage = pte.ppn;
        	int physicalAddress=physicalPage*1024+addressOffset;

        	int transferSize = Math.min(data.length-offset,Math.min(length,1024-addressOffset));
        	System.arraycopy(memory, physicalAddress, data, offset, transferSize);
        	vaddr += transferSize;
        	offset += transferSize;
        	length -=transferSize;
        	amount += transferSize;
			}
          return amount;
		}

		return amount;
	}

	/**
	 * Transfer all data from the specified array to this process's virtual
	 * memory. Same as <tt>writeVirtualMemory(vaddr, data, 0, data.length)</tt>.
	 * 
	 * @param vaddr the first byte of virtual memory to write.
	 * @param data the array containing the data to transfer.
	 * @return the number of bytes successfully transferred.
	 */
	public int writeVirtualMemory(int vaddr, byte[] data) {
		return writeVirtualMemory(vaddr, data, 0, data.length);
	}

	/**
	 * Transfer data from the specified array to this process's virtual memory.
	 * This method handles address translation details. This method must
	 * <i>not</i> destroy the current process if an error occurs, but instead
	 * should return the number of bytes successfully copied (or zero if no data
	 * could be copied).
	 * 
	 * @param vaddr the first byte of virtual memory to write.
	 * @param data the array containing the data to transfer.
	 * @param offset the first byte to transfer from the array.
	 * @param length the number of bytes to transfer from the array to virtual
	 * memory.
	 * @return the number of bytes successfully transferred.
	 */
	public int writeVirtualMemory(int vaddr, byte[] data, int offset, int length) {
		Lib.assertTrue(offset >= 0 && length >= 0
				&& offset + length <= data.length);

		byte[] memory = Machine.processor().getMemory();

		amount = 0;
		  while (length > 0 && offset < data.length) {
        	int addressOffset = vaddr % 1024;
        	int virtualPage = vaddr / 1024;
        	
        	if (virtualPage >= pageTable.length || virtualPage < 0) {
        		break;
        	}
        	
        	TranslationEntry currPTE = pageTable[virtualPage];
        	if (!currPTE.valid || currPTE.readOnly) {
        		break;
        	}
        	currPTE.used = true;
        	currPTE.dirty = true;
        	
        	int physicalPage = currPTE.ppn;
        	int physicalAddress = physicalPage * 1024 + addressOffset;
        	
        	int transferLength = Math.min(data.length-offset, Math.min(length, 1024-addressOffset));
        	System.arraycopy(data, offset, memory, physicalAddress, transferLength);
        	vaddr += transferLength;
        	offset += transferLength;
        	length -= transferLength;
        	amount += transferLength;
        }

		return amount;
	}

	/**
	 * Load the executable with the specified name into this process, and
	 * prepare to pass it the specified arguments. Opens the executable, reads
	 * its header information, and copies sections and arguments into this
	 * process's virtual memory.
	 * 
	 * @param name the name of the file containing the executable.
	 * @param args the arguments to pass to the executable.
	 * @return <tt>true</tt> if the executable was successfully loaded.
	 */
	private boolean load(String name, String[] args) {
		Lib.debug(dbgProcess, "UserProcess.load(\"" + name + "\")");

		OpenFile executable = ThreadedKernel.fileSystem.open(name, false);
		if (executable == null) {
			Lib.debug(dbgProcess, "\topen failed");
			return false;
		}

		try {
			coff = new Coff(executable);
		}
		catch (EOFException e) {
			executable.close();
			Lib.debug(dbgProcess, "\tcoff load failed");
			return false;
		}

		// make sure the sections are contiguous and start at page 0
		numPages = 0;
		for (int s = 0; s < coff.getNumSections(); s++) {
			CoffSection section = coff.getSection(s);
			if (section.getFirstVPN() != numPages) {
				coff.close();
				Lib.debug(dbgProcess, "\tfragmented executable");
				return false;
			}
			numPages += section.getLength();
		}

		// make sure the argv array will fit in one page
		byte[][] argv = new byte[args.length][];
		int argsSize = 0;
		for (int i = 0; i < args.length; i++) {
			argv[i] = args[i].getBytes();
			// 4 bytes for argv[] pointer; then string plus one for null byte
			argsSize += 4 + argv[i].length + 1;
		}
		if (argsSize > pageSize) {
			coff.close();
			Lib.debug(dbgProcess, "\targuments too long");
			return false;
		}

		// program counter initially points at the program entry point
		initialPC = coff.getEntryPoint();

		// next comes the stack; stack pointer initially points to top of it
		numPages += stackPages;
		initialSP = numPages * pageSize;

		// and finally reserve 1 page for arguments
		numPages++;

		if (!loadSections())
			return false;

		// store arguments in last page
		int entryOffset = (numPages - 1) * pageSize;
		int stringOffset = entryOffset + args.length * 4;

		this.argc = args.length;
		this.argv = entryOffset;

		for (int i = 0; i < argv.length; i++) {
			byte[] stringOffsetBytes = Lib.bytesFromInt(stringOffset);
			Lib.assertTrue(writeVirtualMemory(entryOffset, stringOffsetBytes) == 4);
			entryOffset += 4;
			Lib.assertTrue(writeVirtualMemory(stringOffset, argv[i]) == argv[i].length);
			stringOffset += argv[i].length;
			Lib.assertTrue(writeVirtualMemory(stringOffset, new byte[] { 0 }) == 1);
			stringOffset += 1;
		}

		return true;
	}

	/**
	 * Allocates memory for this process, and loads the COFF sections into
	 * memory. If this returns successfully, the process will definitely be run
	 * (this is the last step in process initialization that can fail).
	 * 
	 * @return <tt>true</tt> if the sections were successfully loaded.
	 */
	protected boolean loadSections() {
		if (numPages > Machine.processor().getNumPhysPages()) {
			coff.close();
			Lib.debug(dbgProcess, "\tinsufficient physical memory");
			return false;
		}

		// load sections
		for (int s = 0; s < coff.getNumSections(); s++) {
			CoffSection section = coff.getSection(s);

			Lib.debug(dbgProcess, "\tinitializing " + section.getName()
					+ " section (" + section.getLength() + " pages)");

			for (int i = 0; i < section.getLength(); i++) {
				int vpn = section.getFirstVPN() + i;

				// for now, just assume virtual addresses=physical addresses
				int ppn = pageTable[vpn].ppn;
				section.loadPage(i, ppn);
				if(section.isReadOnly(){
					pageTable[vpn].readOnly = true;
				}
			}
		}

		return true;
	}

	/**
	 * Release any resources allocated by <tt>loadSections()</tt>.
	 */
	protected void unloadSections() {
	}

	/**
	 * Initialize the processor's registers in preparation for running the
	 * program loaded into this process. Set the PC register to point at the
	 * start function, set the stack pointer register to point at the top of the
	 * stack, set the A0 and A1 registers to argc and argv, respectively, and
	 * initialize all other registers to 0.
	 */
	public void initRegisters() {
		Processor processor = Machine.processor();

		// by default, everything's 0
		for (int i = 0; i < processor.numUserRegisters; i++)
			processor.writeRegister(i, 0);

		// initialize PC and SP according
		processor.writeRegister(Processor.regPC, initialPC);
		processor.writeRegister(Processor.regSP, initialSP);

		// initialize the first two argument registers to argc and argv
		processor.writeRegister(Processor.regA0, argc);
		processor.writeRegister(Processor.regA1, argv);
	}

	/**
	 * Handle the halt() system call.
	 */
	private int handleHalt() {


        if (this.PID != rootPID) {
    	   return 0;
        }


		Machine.halt();

		Lib.assertNotReached("Machine.halt() did not halt machine!");
		return 0;
	}

	private static final int syscallHalt = 0, syscallExit = 1, syscallExec = 2,
			syscallJoin = 3, syscallCreate = 4, syscallOpen = 5,
			syscallRead = 6, syscallWrite = 7, syscallClose = 8,
			syscallUnlink = 9;

	/**
	 * Handle a syscall exception. Called by <tt>handleException()</tt>. The
	 * <i>syscall</i> argument identifies which syscall the user executed:
	 * 
	 * <table>
	 * <tr>
	 * <td>syscall#</td>
	 * <td>syscall prototype</td>
	 * </tr>
	 * <tr>
	 * <td>0</td>
	 * <td><tt>void halt();</tt></td>
	 * </tr>
	 * <tr>
	 * <td>1</td>
	 * <td><tt>void exit(int status);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>2</td>
	 * <td><tt>int  exec(char *name, int argc, char **argv);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>3</td>
	 * <td><tt>int  join(int pid, int *status);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>4</td>
	 * <td><tt>int  creat(char *name);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>5</td>
	 * <td><tt>int  open(char *name);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>6</td>
	 * <td><tt>int  read(int fd, char *buffer, int size);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>7</td>
	 * <td><tt>int  write(int fd, char *buffer, int size);
	 * 								</tt></td>
	 * </tr>
	 * <tr>
	 * <td>8</td>
	 * <td><tt>int  close(int fd);</tt></td>
	 * </tr>
	 * <tr>
	 * <td>9</td>
	 * <td><tt>int  unlink(char *name);</tt></td>
	 * </tr>
	 * </table>
	 * /**
	 * Handle the halt() system call.
	 */
  /*
         * if the input arguments are negative, return -1
         * @return the child process Id 
         */
        private int exec(int file, int argc, int argv){
                if(file<0 || argc<0 || argv<0){
                        return -1;
                }
                String fileName= readVirtualMemoryString(file,256);

                if(fileName==null){
                        return -1;
                }

                String args[]= new String[argc];

                int byteReceived,argAddress;
                byte temp[]=new byte[4];
                for(int i =0; i<argc; i++){
                        byteReceived=readVirtualMemory(argv+i*4,temp);
                        if(byteReceived !=4){
                                return -1;
                        }

                        argAddress=Lib.bytesToInt(temp, 0);
                        args[i]=readVirtualMemoryString(argAddress, 256);

                        if(args[i]==null){
                                return -1;
                        }

                }
                UserProcess child=UserProcess.newUserProcess();
        		childProcess newProcessData = new childProcess(child);
                child.myChildProcess = newProcessData;
                
                if(child.execute(fileName, args)){
                    map.put(child.process_id, newProcessData);
                    return child.process_id;
                }

                return -1;
        }


        /*
         * pid  is the child process going to join 
         * status is the vritual address that we need to write the result on it.
         */

        private int join(int pid,int status){
                if (pid <0 || status<0){
                        return -1;
                }
                //get the child process from our hashmap
                childProcess childData;
                if(map.containsKey(pid)){
                	childData = map.get(pid);
                }
                else{
                        return -1;
                }

                //join it
                childData.child.thread.join();
                
                //remove from hashmap
                map.remove(pid);

                //write the exit # to the address status
                if(childData.status!=-999){
                        byte exitStatus[] = new byte[4];
                        exitStatus=Lib.bytesFromInt(childData.status);
                        int byteTransfered=writeVirtualMemory(status,exitStatus);

                        if(byteTransfered == 4){
                                return 1;
                        }
                        else{
                                return 0;
                        }

                }
                return 0;
        }
        
        private void exit(int status){
                if(myChildProcess!=null){
                	myChildProcess.status = status;
                }
                
                //close all the opened files
                for (int i=0; i<16; i++) {              
                        close(i);
                }
                
                //part2 implemented
                this.unloadSections();
                
                if(this.process_id==ROOT){
                        Kernel.kernel.terminate();
                }
                
                else{
                        KThread.finish();
                    	Lib.assertNotReached();
                }
        }

    private int close(int a0){
    	OpenFile file = openFiles.get(a0);
    	if(file == null ) return -1;
    	file.close();
    	openFiles.remove(a0);
    	fdList.add(a0);
    }
/* The system call interface. These are the operations the Nachos kernel needs
 * to support, to be able to run user programs.
 *
 * Each of these is invoked by a user program by simply calling the procedure;
 * an assembly language stub stores the syscall code (see above) into $r0 and
 * executes a syscall instruction. The kernel exception handler is then
 * invoked.
 */

/* Halt the Nachos machine by calling Machine.halt(). Only the root process
 * (the first process, executed by UserKernel.run()) should be allowed to
 * execute this syscall. Any other process should ignore the syscall and return
 * immediately.
 */
	private int halt() {

        if (this.PID != rootPID) {
    	   return 0;
        }


		Machine.halt();

		Lib.assertNotReached("Machine.halt() did not halt machine!");
		return 0;
	}
	/* PROCESS MANAGEMENT SYSCALLS: exit(), exec(), join() */

/**
 * Terminate the current process immediately. Any open file descriptors
 * belonging to the process are closed. Any children of the process no longer
 * have a parent process.
 *
 * status is returned to the parent process as this process's exit status and
 * can be collected using the join syscall. A process exiting normally should
 * (but is not required to) set status to 0.
 *
 * exit() never returns.
 */
void exit(int status);

/**
 * Execute the program stored in the specified file, with the specified
 * arguments, in a new child process. The child process has a new unique
 * process ID, and starts with stdin opened as file descriptor 0, and stdout
 * opened as file descriptor 1.
 *
 * file is a null-terminated string that specifies the name of the file
 * containing the executable. Note that this string must include the ".coff"
 * extension.
 *
 * argc specifies the number of arguments to pass to the child process. This
 * number must be non-negative.
 *
 * argv is an array of pointers to null-terminated strings that represent the
 * arguments to pass to the child process. argv[0] points to the first
 * argument, and argv[argc-1] points to the last argument.
 *
 * exec() returns the child process's process ID, which can be passed to
 * join(). On error, returns -1.
 */
int exec(int file, int argc,  int argv){
			if(file<0 || argc<0 || argv<0){
                        return -1;
                }
                String fileName= readVirtualMemoryString(file,256);

                if(fileName==null){
                        return -1;
                }

                String args[]= new String[argc];


                byte tempInt[]=new byte[4];
                for(int i =0; i<argc; i++){
                        int byteReceived=readVirtualMemory(argv+i*4,tempInt);
                        if(byteReceived !=4){
                                return -1;
                        }

                        int argAddress=Lib.bytesToInt(tempInt, 0);
                        args[i]=readVirtualMemoryString(argAddress, 256);

                        if(args[i]==null){
                                return -1;
                        }

                }
                UserProcess child=UserProcess.newUserProcess();
        		ChildProcess newChildProcess = new ChildProcess(child);
        		child.myChildProcess = newProcessData;

        		if(child.execute(fileName, args)){
                    childProcessMap.put(child.PID, child);
                    return child.PID;
                }

                return -1;
}

/**
 * Suspend execution of the current process until the child process specified
 * by the processID argument has exited. If the child has already exited by the
 * time of the call, returns immediately. When the current process resumes, it
 * disowns the child process, so that join() cannot be used on that process
 * again.
 *
 * processID is the process ID of the child process, returned by exec().
 *
 * status points to an integer where the exit status of the child process will
 * be stored. This is the value the child passed to exit(). If the child exited
 * because of an unhandled exception, the value stored is not defined.
 *
 * If the child exited normally, returns 1. If the child exited as a result of
 * an unhandled exception, returns 0. If processID does not refer to a child
 * process of the current process, returns -1.
 */
int join(int processID, int *status){
   if(processID < || status <0 )
   	 return -1;
   	ChildProcess childProcess;
   	if(childProcessMap.containsKey(processID)){
   		childData = childProcessMap.get(processID);
   	}
   	else{
   		return -1;
   	}
   	childProcess.child.thread.join();

   	childProcessMap.remove(processID);

   	 if(childProcess.status!=-1){
                        byte exitStatus[] = new byte[4];
                        exitStatus=Lib.bytesFromInt(childProcess.exit_status);
                        int byteTransfered=writeVirtualMemory(status,exitStatus);

                        if(byteTransfered == 4){
                                return 1;
                        }
                        else{
                                return 0;
                        }

                }


}

/* FILE MANAGEMENT SYSCALLS: creat, open, read, write, close, unlink
 *
 * A file descriptor is a small, non-negative integer that refers to a file on
 * disk or to a stream (such as console input, console output, and network
 * connections). A file descriptor can be passed to read() and write() to
 * read/write the corresponding file/stream. A file descriptor can also be
 * passed to close() to release the file descriptor and any associated
 * resources.
 */

/**
 * Attempt to open the named disk file, creating it if it does not exist,
 * and return a file descriptor that can be used to access the file.
 *
 * Note that creat() can only be used to create files on disk; creat() will
 * never return a file descriptor referring to a stream.
 *
 * Returns the new file descriptor, or -1 if an error occurred.
 */



	/* FILE MANAGEMENT SYSCALLS: creat, open, read, write, close, unlink
 *
 * A file descriptor is a small, non-negative integer that refers to a file on
 * disk or to a stream (such as console input, console output, and network
 * connections). A file descriptor can be passed to read() and write() to
 * read/write the corresponding file/stream. A file descriptor can also be
 * passed to close() to release the file descriptor and any associated
 * resources.
 */

/**
 * Attempt to open the named disk file, creating it if it does not exist,
 * and return a file descriptor that can be used to access the file.
 *
 * Note that creat() can only be used to create files on disk; creat() will
 * never return a file descriptor referring to a stream.
 *
 * Returns the new file descriptor, or -1 if an error occurred.
 */
pricate int creat(int a0){
String filename = this.readVirtualMemoryString(a0,255);
	if(filename == null) return -1;
	Openfile file = ThreadedKernel.fileSystem.open(filename,ture);
	if(file == null){
           return -1;
	}
	if(fdList.size() < 1 )
	int fileDescriptor = fdList.remove(0);
	openFiles.put(fileDescriptor,file)
	return fileDescriptor;
}

/**
 * Attempt to open the named file and return a file descriptor.
 *
 * Note that open() can only be used to open files on disk; open() will never
 * return a file descriptor referring to a stream.
 *
 * Returns the new file descriptor, or -1 if an error occurred.
 */
int open(char *name){
	String filename = this.readVirtualMemoryString(a0,255);
	if(filename == null) return -1;
	Openfile file = ThreadedKernel.fileSystem.open(filename,ture);
	if(file == null){
           return -1;
	}
	if(fileDescriptorList.size() < 1 )
	int fileDescriptor = fileDescriptorList.remove(0);
	openFiles.put(fileDescriptor,file)
	return fileDescriptor;

}

/**
 * Attempt to read up to count bytes into buffer from the file or stream
 * referred to by fileDescriptor.
 *
 * On success, the number of bytes read is returned. If the file descriptor
 * refers to a file on disk, the file position is advanced by this number.
 *
 * It is not necessarily an error if this number is smaller than the number of
 * bytes requested. If the file descriptor refers to a file on disk, this
 * indicates that the end of the file has been reached. If the file descriptor
 * refers to a stream, this indicates that the fewer bytes are actually
 * available right now than were requested, but more bytes may become available
 * in the future. Note that read() never waits for a stream to have more data;
 * it always returns as much as possible immediately.
 *
 * On error, -1 is returned, and the new file position is undefined. This can
 * happen if fileDescriptor is invalid, if part of the buffer is read-only or
 * invalid, or if a network stream has been terminated by the remote host and
 * no more data is available.
 */
int read(int fd, int bufferAddress, int count);{
	OpenFile file = openFiles.get(fd);
	if(file == null ) return -1;
	byte[]  buffer = new byte[Processor.pageSize]
	boolean done = false;
	int amount =0 ;  // total size be read
	while(!done && count>0 ){
		int size = Math.min(Processor.pageSize,count);

		int readsize = file.read(bufferAddress,0,size);
		if(readsize == -1) return -1;
		if(read<size) done = true;

		int written_bytes = writeVirtualMemory(bufaddr, buffer,0,readsize);
		if(written_bytes != readsize){
			return -1;
		}
		count -= readsize;
		bufferAddress += actualread;
		transfersize +=readsize;
	}
	return amount;
}

/**
 * Attempt to write up to count bytes from buffer to the file or stream
 * referred to by fileDescriptor. write() can return before the bytes are
 * actually flushed to the file or stream. A write to a stream can block,
 * however, if kernel queues are temporarily full.
 *
 * On success, the number of bytes written is returned (zero indicates nothing
 * was written), and the file position is advanced by this number. It IS an
 * error if this number is smaller than the number of bytes requested. For
 * disk files, this indicates that the disk is full. For streams, this
 * indicates the stream was terminated by the remote host before all the data
 * was transferred.
 *
 * On error, -1 is returned, and the new file position is undefined. This can
 * happen if fileDescriptor is invalid, if part of the buffer is invalid, or
 * if a network stream has already been terminated by the remote host.
 */
int write(int fd, int bufferAddress, int count);

OpenFile file = openFiles.get(fd);
	if(file == null ) return -1;
	byte[]  buffer = new byte[Processor.pageSize]
	boolean done = false;
	int amount =0 ;
	while( count>0 ){
		int size = Math.min(Processor.pageSize,count);

		int readsize = readVirtualMemory(bufferAddress,buffer,0,size);
		if(readsize == -1) return -1;
		if(readsize<size) return -1;

		int written_bytes = file.write(buffer,0,readsize);
		if(written_bytes != readsize){
			return -1;
		}
		count -= readsize;
		bufferAddress += readsize;
		transfersize +=readsize;
	}
	return amount;
}

int close(int fd){
  OpenFile file = openFIles.get(fd);
  if(file==null) return -1;
  file.close();
  openFiles.remove(fd);
  fdList.add(fd);
  return 0;
}

/**
 * Delete a file from the file system. If no processes have the file open, the
 * file is deleted immediately and the space it was using is made available for
 * reuse.
 *
 * If any processes still have the file open, the file will remain in existence
 * until the last file descriptor referring to it is closed. However, creat()
 * and open() will not be able to return new file descriptors for the file
 * until it is deleted.
 *
 * Returns 0 on success, or -1 if an error occurred.
 */
int unlink(int name){
  String filename=this.readVirtualMemoryString(name,255);
  if(filename = null){
  	return -1;
  }
  return ThreadedKernel.fileSystem.remove(filename)?0:-1;

}

	 /* 
	 * @param syscall the syscall number.
	 * @param a0 the first syscall argument.
	 * @param a1 the second syscall argument.
	 * @param a2 the third syscall argument.
	 * @param a3 the fourth syscall argument.
	 * @return the value to be returned to the user.
	 */
	/*
	SYSCALLSTUB(halt, syscallHalt)
	SYSCALLSTUB(exit, syscallExit)
	SYSCALLSTUB(exec, syscallExec)
	SYSCALLSTUB(join, syscallJoin)
	SYSCALLSTUB(creat, syscallCreate)
	SYSCALLSTUB(open, syscallOpen)
	SYSCALLSTUB(read, syscallRead)
	SYSCALLSTUB(write, syscallWrite)
	SYSCALLSTUB(close, syscallClose)
	SYSCALLSTUB(unlink, syscallUnlink)
	SYSCALLSTUB(mmap, syscallMmap)
	SYSCALLSTUB(connect, syscallConnect)
	SYSCALLSTUB(accept, syscallAccept)
	*/
	 */
	public int handleSyscall(int syscall, int a0, int a1, int a2, int a3) {
		switch (syscall) {
		case syscallHalt:
			return halt();
		case syscallCreate:
		   return create(a0);
		case syscallOpen:
		   return open(a0);
		case syscallRead:
		   return read(a0,a1,a2);
		case syscallClose:
		   return write(a0,a1,a2);
		case syscallUnlink:
		   return unlink(a0);

		default:
			Lib.debug(dbgProcess, "Unknown syscall " + syscall);
			Lib.assertNotReached("Unknown system call!");
		}
		return 0;
	}

	/**
	 * Handle a user exception. Called by <tt>UserKernel.exceptionHandler()</tt>
	 * . The <i>cause</i> argument identifies which exception occurred; see the
	 * <tt>Processor.exceptionZZZ</tt> constants.
	 * 
	 * @param cause the user exception that occurred.
	 */
	public void handleException(int cause) {
		Processor processor = Machine.processor();

		switch (cause) {
		case Processor.exceptionSyscall:
			int result = handleSyscall(processor.readRegister(Processor.regV0),
					processor.readRegister(Processor.regA0),
					processor.readRegister(Processor.regA1),
					processor.readRegister(Processor.regA2),
					processor.readRegister(Processor.regA3));
			processor.writeRegister(Processor.regV0, result);
			processor.advancePC();
			break;

		default:
			Lib.debug(dbgProcess, "Unexpected exception: "
					+ Processor.exceptionNames[cause]);
			Lib.assertNotReached("Unexpected exception");
		}
	}

	/** The program being run by this process. */
	protected Coff coff;

	/** This process's page table. */
	protected TranslationEntry[] pageTable;

	/** The number of contiguous pages occupied by the program. */
	protected int numPages;

	/** The number of pages in the program's stack. */
	protected final int stackPages = 8;

	private int initialPC, initialSP;

	private int argc, argv;

	private static final int pageSize = Processor.pageSize;

	private static final char dbgProcess = 'a';

	 private HashMap<int, OpenFile> openFiles;
    private List<int> fdList;

    private static final int rootPID = 1;
    private static int uniquePID = rootPID;

    private int PID;

    private HashMap<int, ChildProcess> childProcessMap;
    private ChildProcess myCProcess;

    class ChildProcess{
    	UserProcess child;
    	int exit_status;
    	ChildProcess(UserProcess process){
    		this.child = process;
    		this.exit_status=-1;
    	}
    }

}


