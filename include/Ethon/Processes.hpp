/*
Processes.hpp
This File is a part of Ethonmem, a memory hacking library for linux
Copyright (C) < 2011, Ethon >
              < ethon@ethon.cc - http://ethon.cc >

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef __ETHON_PROCESSES_HPP__
#define __ETHON_PROCESSES_HPP__

// POSIX:
#include <unistd.h>

// C++ Standard Library:
#include <string>
#include <cstdint>
#include <vector>
#include <utility>

// Boost Library:
#include <boost/filesystem.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/optional.hpp>

namespace Ethon
{
  typedef ::pid_t Pid;

  class ProcessStatus;

  /**
  * A currently running processes.
  */
  class Process
  {
  private:
    Pid m_pid; // The process' ID.
    boost::filesystem::path m_path; // The process' procfs directory.

  public:

    /**
    * Creates an empty object.
    */
    Process();

    /**
    * Opens a process by a process Id.
    * @param process Id to open.
    */
    explicit Process(Pid process);

    /**
    * Opens a process by a procfs path '/proc/[pid]'.
    * @param path Path to open.
    */
    explicit Process(boost::filesystem::path const& path);

    /**
    * Retrieves the process' pid.
    * @return The process' pid.
    */
    Pid getPid() const;
    
    /**
    * Retrieves the executeables path.
    * @return The executeables path.
    */
    boost::filesystem::path getExecutablePath() const;

    /**
    * Retrieves the process' procfs path.
    * @return The process' procfs path.
    */
    boost::filesystem::path const& getProcfsDirectory() const;

    /**
    * Queries information about the process' status.
    * @return The process status.
    */
    ProcessStatus getStatus() const;
    
    /**
    * Queries information about the process' status.
    * @param dest Reference to a ProcessStatus-object to store data.
    * @return The object used to store data.
    */
    ProcessStatus& getStatus(ProcessStatus& dest) const;

    /**
     * Compares two process objects.
     * @param rhs Another process to compare with.
     * @result True if equal, false otherwise.
     */
    bool operator==(Process const& rhs) const;

    /**
     * Compares two process objects.
     * @param rhs Another process to compare with.
     * @result True if unequal, false otherwise.
     */
    bool operator!=(Process const& rhs) const;
  };

  /**
  * Stores information about a process.
  */
  class ProcessStatus
  {
  private:

    /* For description of those variable, do 'man proc' */
    Pid             m_pid;
    std::string     m_name;
    char            m_state;

    Pid             m_ppid;
    Pid             m_pgrp;
    Pid             m_session;
    Pid             m_tty_nr;
    Pid             m_tpgid;

    unsigned int    m_flags;
    unsigned long   m_minflt;
    unsigned long   m_cminflt;
    unsigned long   m_majflt;
    unsigned long   m_cmajflt;
    unsigned long   m_utime;
    unsigned long   m_stime;
    long            m_cutime;
    long            m_cstime;
    long            m_priority;
    long            m_nice;
    long            m_num_threads;

    //long          m_itrealvalue

    unsigned long long m_starttime;
    unsigned long   m_vsize;
    long            m_rss;
    unsigned long   m_rsslim;
    uintptr_t       m_startcode;
    uintptr_t       m_endcode;
    uintptr_t       m_startstack;
    uintptr_t       m_kstkesp;
    uintptr_t       m_kstkeip;

    //unsigned long m_signal
    //unsigned long m_blocked
    //unsigned long m_sigignore
    //unsigned long m_sigcatch

    unsigned long   m_wchan;

    //unsigned long m_nswap
    //unsigned long m_cnswap

    int             m_exit_signal;
    int             m_processor;
    unsigned int    m_rt_priority;
    unsigned int    m_policy;
    unsigned long long m_delayacct_blkio_ticks;
    unsigned long   m_guest_time;
    long            m_cguest_time;

  public:

    /**
    * Creates an empty status object
    */
    ProcessStatus();

    /**
    * Creates an object by reading a process object.
    * @param process A process object to read from.
    */
    ProcessStatus(Process const& process);

    /**
    * Reads information from a process.
    * @param process A process object to read from.
    * @return The current object.
    */
    ProcessStatus& read(Process const& process);

    /**
    * The process ID.
    * @return The process ID.
    */
    Pid getPid() const;

    /**
    * The filename of the executable.
    * @return The filename of the executable
    */
    std::string const& getExecutableName() const;

    /**
    * Checks if the process is running.
    * @return True if running, false otherwise.
    */
    bool isRunning() const;

    /**
    * Checks if the process is sleeping.
    * @return True if sleeping, false otherwise.
    */
    bool isSleeping() const;

    /**
    * Checks if the process is waiting.
    * @return True if waiting, false otherwise.
    */
    bool isWaiting() const;

    /**
    * Checks if the process is a zombie.
    * @return True if a zombie, false otherwise.
    */
    bool isZombie() const;

    /**
    * Checks if the process is stopped.
    * @return True if stopped, false otherwise.
    */
    bool isStopped() const;

    /**
    * Checks if the process is paging.
    * @return True if paging, false otherwise.
    */
    bool isPaging() const;

    /**
    * One character  from  the string "RSDZTW" where R is running, S is
    * sleeping in an interruptible wait, D is waiting in uninterruptible disk
    * sleep, Z is zombie, T is traced or stopped (on a signal), and W
    * is paging.
    * @return The status character.
    */
    char getState() const;
    
    /**
    * Returns a string describing the current state.
    * Possible values are 'Running', 'Sleeping', 'Waiting', 'Zombie',
    * 'Traced/Stopped', 'Paging' and 'Unknown'.
    * @return The status string.
    */
    char const* getStateString() const;

    /**
    * The PID of the parent.
    * @return The PID of the parent.
    */
    Pid getParentPid() const;

    /**
    * The process group ID of the process.
    * @return The process group ID of the process.
    */
    Pid getProcessGroupId() const;

    /**
    * The session ID of the process.
    * @return The session ID of the process.
    */
    Pid getSessionId() const;

    /**
    * The controlling terminal of the process as pair.
    * The first value holds the major device number, the second holds
    * the minor.
    * @return The controlling terminal of the process.
    */
    std::pair<int, int> getTty() const;

    /**
    * The ID of the foreground process group of the controlling terminal of
    * the process.
    * @return The ID of the foreground process group.
    */
    Pid getTtyProcessGroupId() const;

    /**
    * The kernel flags word of the process. For bit meanings, see the
    * PF_* defines in <linux/sched.h>. Details depend on the kernel version.
    * @return The kernel flags word of the process.
    */
    int getKernelFlagsWord() const;

    /**
    * The number of minor faults the process has made which have not required
    * loading a memory page from disk.
    * @return The number of minor faults.
    */
    unsigned long getNumMinorFaults() const;

    /**
    * The number of minor faults that the process's waited-for children
    * have made.
    * @return The number of minor faults.
    */
    unsigned long getNumChildrenMinorFaults() const;

    /**
    * The number of major faults the process has made which have required
    * loading a memory page from disk.
    * @return The number of major faults.
    */
    unsigned long getNumMajorFaults() const;

    /**
    * The number of major faults that the process's waited-for children
    * have made.
    * @return The number of major faults.
    */
    unsigned long getNumChildrenMajorFaults() const;

    /**
    * Amount of time that this process has been scheduled in user mode,
    * measured in clock  ticks  (divide  by sysconf(_SC_CLK_TCK). This
    * includes guest time, guest_time (time spent running a virtual CPU, see
    * below), so that applications that are not aware of the guest time field
    * do not lose that time from their calculations.
    * @return The amount of time.
    */
    unsigned long getUserTime() const;

    /**
    * Amount of time that this process has been scheduled in kernel mode,
    * measured in clock ticks (divide by sysconf(_SC_CLK_TCK).
    * @return The amount of time.
    */
    unsigned long getSystemTime() const;

    /**
    * Amount of time that this process's waited-for children have been
    * scheduled in user mode, measured in clock  ticks  (divide by
    * sysconf(_SC_CLK_TCK). (See  also  times(2).) This includes guest time,
    * cguest_time (time spent running a virtual CPU, see below).
    * @return The amount of time.
    */
    unsigned long getChildrenUserTime() const;

    /**
    * Amount of time that this process's waited-for children have been
    * scheduled in kernel mode, measured in clock ticks (divide  by
    * sysconf(_SC_CLK_TCK).
    * @return The amount of time.
    */
    unsigned long getChildrenSystemTime() const;

    /**
    * (Explanation  for  Linux  2.6)  For processes running a real-time
    * scheduling policy (policy below; see sched_setscheduler(2)), this is the
    * negated scheduling priority, minus one; that is, a number in the range
    * -2 to -100, corresponding to real-time priorities  1  to 99. For
    * processes running under a non-real-time scheduling policy, this is the
    * raw nice value (setpriority(2)) as represented in the kernel. The kernel
    * stores nice values as numbers in the range 0 (high) to 39  (low),
    * corresponding to the user-visible nice range of -20 to 19.
    * Before Linux 2.6, this was a scaled value based on the scheduler
    * weighting given to this process.
    * @return The priority;
    */
    long getPriority() const;

    /**
    * The nice value (see setpriority(2)), a value in the range 19
    * (low priority) to -20 (high priority).
    * @return The nice value.
    */
    long getNice() const;

    /**
    * Number of threads in this process (since Linux 2.6). Before kernel 2.6,
    * this field was hard coded to 0 as a placeholder for an
    * earlier removed field.
    * @return The number of threads
    */
    long getNumThreads() const;

    /**
    * The time in jiffies the process started after system boot.
    * @return The time in jiffies.
    */
    uint64_t getStartTime() const;

    /**
    * Virtual memory size in bytes.
    * @return The virtual memory size in bytes.
    */
    unsigned long getVirtualMemorySize() const;

    /**
    * Resident Set Size: number of pages the process has in real memory. This
    * is just the pages which count towards text, data, or stack space. This
    * does not include pages which have not been demand-loaded in, or which
    * are swapped out.
    * @return The number of pages the process has in real memory.
    */
    long getResidentSetSize() const;

    /**
    * Current soft limit in bytes on the rss of the process;
    * see the description of RLIMIT_RSS in getpriority(2).
    * @return The current soft limit in bytes.
    */
    unsigned long getResidentSetLimit() const;

    /**
    * The address above which program text can run.
    * @return The address above which program text can run.
    */
    uintptr_t getCodeStart() const;

    /**
    * The address below which program text can run.
    * @return The address below which program text can run.
    */
    uintptr_t getCodeEnd() const;

    /**
    * The address of the start (i.e., bottom) of the stack.
    * @return The address of the start of the stack.
    */
    uintptr_t getStackStart() const;

    /**
    * The current value of ESP (stack pointer), as found in the
    * kernel stack page for the process.
    * @return The current value of ESP.
    */
    uintptr_t getStackPointer() const;

    /**
    * The current EIP (instruction pointer).
    * @return The current EIP.
    */
    uintptr_t getInstructionPointer() const;

    /**
    * This is the "channel" in which the process is waiting. It is the address
    * of a system call, and can be looked up in a namelist if you need a
    * textual name. (If you have an up-to-date /etc/psdatabase, then try ps -l
    * to see the WCHAN field in action.)
    * @return The "channel" in which the process is waiting.
    */
    unsigned long getWaitChannel() const;

    /**
    * Signal to be sent to parent when we die.
    * @return The signal to be sent.
    */
    int getExitSignal() const;

    /**
    * CPU number last executed on.
    * @return The CPU number last executed on.
    */
    int getCpuNumber() const;

    /**
    * Real-time scheduling priority, a number in the range 1 to 99 for
    * processes scheduled under a real-time policy, or 0, for non-real-time
    * processes (see sched_setscheduler(2)).
    * @return The real-time scheduling priority.
    */
    unsigned int getRealtimePriority() const;

    /**
    * Scheduling policy (see sched_setscheduler(2)).
    * Decode using the SCHED_* constants in linux/sched.h.
    * @return The scheduling policy.
    */
    unsigned int getSchedulingPolicy() const;

    /**
    * Aggregated block I/O delays, measured in clock ticks (centiseconds).
    * @return The delays measured in clock ticks.
    */
    uint64_t getIoDelays() const;

    /**
    * Guest time of the process (time spent running a virtual CPU for a guest
    * operating system), measured in clock ticks
    * (divide  by sysconf(_SC_CLK_TCK).
    * @return The guest time of the process.
    */
    unsigned long getGuestTime() const;

    /**
    * Guest time of the process's children, measured in clock ticks
    * (divide by sysconf(_SC_CLK_TCK).
    * @return The guest time of the process's children.
    */
    long getChildrenGuestTime() const;
  };

  class ProcessIterator
    : public boost::iterator_facade<  ProcessIterator,
                                      Process,
                                      boost::forward_traversal_tag >
  {
  private:

    friend class boost::iterator_core_access;

    /**
    * Increments the iterator to point to the next entry.
    */
    void increment();

    /**
    * Checks if both iterators have the same validity-state.
    * @param other An other iterator to check equality with.
    * @return True if both have the same validity-state, false otherwise.
    */
    bool equal(ProcessIterator const& other) const;

    /**
    * Returns a reference to the current entry.
    * @return A reference to the current entry.
    */
    Process& dereference() const;

    mutable Process m_current;
    boost::filesystem::directory_iterator m_iter;

  public:

    /**
    * Default constructor creating an invalid iterator.
    */
    ProcessIterator();

    /**
    * Constructor creating an iterator for iterating running processes.
    * @param dummy Pass anything to create a valid iterator.
    */
    explicit ProcessIterator(int dummy);

    /**
    * Checks if the iterator is (still) valid.
    * @return True if valid, else otherwise.
    */
    bool isValid() const;
  };

  typedef std::pair<ProcessIterator, ProcessIterator> ProcessSequence;

  /**
  * Enumerates all running processes on the system.
  * @param f Functor to be called every entry with a Process as argument.
  * @return The functor f.
  */
  template<typename functor_t>
  functor_t enumProcesses(functor_t f)
  {
    return std::for_each(ProcessIterator(1), ProcessIterator(), f);
  }

  /**
  * Makes a pair of ProcessIterators, which can be used to iterate processes.
  * @return A pair of ProcessIterators.
  */
  ProcessSequence makeProcessSequence();

  /**
  * Returns a process object attached to the current process.
  * @return The current process.
  */
  Process const& getCurrentProcess();

  /**
  * Retrieves the first process with a given name. All characters after the
  * 15. are discarded
  * @param processName The process' name.
  * @return The process, if found.
  */
  boost::optional<Process> getProcessByName(std::string const& processName);

  /**
  * Retrieves all processes with a given name. All characters after the
  * 15. are discarded
  * @param processName The process' name.
  * @return All found processes.
  */
  std::vector<Process> getProcessListByName(std::string const& processName);

  /**
  * Determines if the process image is 32 or 64bit.
  * @param proc process whose image should be examined.
  * @return 32 or 64
  */
  std::uint8_t getProcessImageBits(Process const& proc);
}

#endif // __ETHON_PROCESSES_HPP__
