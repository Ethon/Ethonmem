/*
Processes.cpp
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

// POSIX:
#include <unistd.h>
#include <elf.h>

// C++ Standard Library:
#include <string>
#include <vector>
#include <utility>
#include <cassert>

// Boost Library:
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/optional.hpp>

// Ethon:
#include <Ethon/Error.hpp>
#include <Ethon/Processes.hpp>

using Ethon::Process;
using Ethon::ProcessStatus;
using Ethon::ProcessIterator;
using Ethon::EthonError;
using Ethon::ProcessSequence;
using Ethon::Pid;

bool isNumericOnly(std::string const& str)
{
  BOOST_FOREACH(char cur, str)
  {
    if(!isdigit(cur))
      return false;
  }

  return true;
}

/* Process class */

Process::Process()
  : m_pid(0), m_path()
{ }

Process::Process(Pid process)
 : m_pid(process), m_path("/proc")
{
  // Make path.and validate
  m_path /= boost::lexical_cast<std::string>(process);
  if(!boost::filesystem::exists(m_path))
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Invalid PID or insufficient permissions"));
  }
}

Process::Process(boost::filesystem::path const& path)
 : m_pid(0), m_path(path)
{
  // Validate path
  if(!boost::filesystem::exists(path) || !isNumericOnly(path.filename()))
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Invalid path or insufficient permissions"));
  }

  // Set pid
  m_pid = boost::lexical_cast< Pid>(path.filename());
}

Pid Process::getPid() const
{
  return m_pid;
}

boost::filesystem::path Process::getExecutablePath() const
{
  // Make path to executeable and validate.
  boost::filesystem::path exePath = getProcfsDirectory() / "exe";
  if(!boost::filesystem::exists(exePath))
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Error finding executeable of process."));
  } 
  
  int ec; 
  std::vector<char> buffer(512);
  for(;;)
  {
    ec = readlink(exePath.string().c_str(), &buffer[0], buffer.size());
    if(ec == -1)
    {
      std::error_code const error = Ethon::makeErrorCode();
      BOOST_THROW_EXCEPTION(EthonError() <<
        ErrorString("readlink failed") <<
        ErrorCode(error));
    }
    
    // Make sure we read everything.
    if(ec == static_cast<int>(buffer.size()))
      buffer = std::vector<char>(buffer.size() * 2);
    else
      break;
  }
  
  auto beg = buffer.begin();
  std::string path(beg, beg + ec);
  return boost::filesystem::path(path);
}

const boost::filesystem::path& Process::getProcfsDirectory() const
{
  return m_path;
}

ProcessStatus Process::getStatus() const
{
  ProcessStatus status;
  getStatus(status);
  return status;
}

ProcessStatus& Process::getStatus(ProcessStatus& dest) const
{
  return dest.read(*this);
}

/* ProcessStatus class */

ProcessStatus::ProcessStatus()
  : m_pid(0), m_name(), m_state(0), m_ppid(0), m_pgrp(0), m_session(0),
    m_tty_nr(0), m_tpgid(0), m_flags(0), m_minflt(0), m_cminflt(0),
    m_majflt(0), m_cmajflt(0), m_utime(0), m_stime(0), m_cutime(0),
    m_cstime(0), m_priority(0), m_nice(0), m_num_threads(0), m_starttime(0),
    m_vsize(0), m_rss(0), m_rsslim(0), m_startcode(0), m_endcode(0),
    m_startstack(0), m_kstkesp(0), m_kstkeip(0), m_wchan(0), m_exit_signal(0),
    m_processor(0), m_rt_priority(0), m_policy(0), m_delayacct_blkio_ticks(0),
    m_guest_time(0), m_cguest_time(0)
{ }

ProcessStatus::ProcessStatus(Process const& process)
  : m_pid(0), m_name(), m_state(0), m_ppid(0), m_pgrp(0), m_session(0),
    m_tty_nr(0), m_tpgid(0), m_flags(0), m_minflt(0), m_cminflt(0),
    m_majflt(0), m_cmajflt(0), m_utime(0), m_stime(0), m_cutime(0),
    m_cstime(0), m_priority(0), m_nice(0), m_num_threads(0), m_starttime(0),
    m_vsize(0), m_rss(0), m_rsslim(0), m_startcode(0), m_endcode(0),
    m_startstack(0), m_kstkesp(0), m_kstkeip(0), m_wchan(0), m_exit_signal(0),
    m_processor(0), m_rt_priority(0), m_policy(0), m_delayacct_blkio_ticks(0),
    m_guest_time(0), m_cguest_time(0)
{
  read(process);
}

ProcessStatus& ProcessStatus::read(Process const& process)
{
  // Open stat-file
  boost::filesystem::ifstream statFile(process.getProcfsDirectory() / "stat");
  if(!statFile.is_open())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
    ErrorString("Can't open statfile"));
  }

  // Read it ;)
  statFile >> m_pid;

  // Name is embraced by parantheses with a max length of 15
  statFile.ignore(32, '(');
  getline(statFile, m_name, ')');
  statFile.ignore(32, ' ');

  char dummy;
  statFile >> m_state >> m_ppid >> m_pgrp >> m_session >> m_tty_nr >>
    m_tpgid >> m_flags >> m_minflt >> m_cminflt >> m_majflt >> m_cmajflt >>
    m_utime >> m_stime >> m_cutime >> m_cstime >> m_priority >> m_nice >>
    m_num_threads >> dummy >> m_starttime >> m_vsize >> m_rss >> m_rsslim >>
    m_startcode >> m_endcode >> m_startstack >> m_kstkesp >> m_kstkeip >>
    dummy >> dummy >> dummy >> dummy >> m_wchan >> dummy >> dummy >>
    m_exit_signal >> m_processor >> m_rt_priority >> m_policy >>
    m_delayacct_blkio_ticks >> m_guest_time >> m_cguest_time;

  return *this;
}

Pid ProcessStatus::getPid() const
{
  return m_pid;
}

std::string const& ProcessStatus::getExecutableName() const
{
  return m_name;
}

bool ProcessStatus::isRunning() const
{
  return m_state == 'R';
}

bool ProcessStatus::isSleeping() const
{
  return m_state == 'S';
}

bool ProcessStatus::isWaiting() const
{
  return m_state == 'D';
}

bool ProcessStatus::isZombie() const
{
  return m_state == 'Z';
}

bool ProcessStatus::isStopped() const
{
  return m_state == 'T';
}

bool ProcessStatus::isPaging() const
{
  return m_state == 'W';
}

char ProcessStatus::getState() const
{
  return m_state;
}

char const* getStateString() const
{
    char const* result = "Unknown";
    switch(m_state)
    {
    case 'R':
        result = "Running";
        break;

    case 'S':
        result = "Sleeping";
        break;

    case 'D':
        result = "Waiting";
        break;

    case 'Z':
        result = "Zombie";
        break;

    case 'T':
        result = "Traced/Stopped";
        break;

    case 'W':
        result = "Paging";
        break;
    };
    
    return result;
}

Pid ProcessStatus::getParentPid() const
{
  return m_ppid;
}

Pid ProcessStatus::getProcessGroupId() const
{
  return m_pgrp;
}

Pid ProcessStatus::getSessionId() const
{
  return m_session;
}

std::pair<int, int> ProcessStatus::getTty() const
{
  int tty = m_tty_nr; 
  int minor = static_cast<char>(tty);
  
  tty >>= 8;
  int major = static_cast<char>(tty);
  
  tty >>= 12;
  minor += static_cast<char>(tty);
  
  return std::pair<int, int>(major, minor);
}

Pid ProcessStatus::getTtyProcessGroupId() const
{
  return m_tpgid;
}

int ProcessStatus::getKernelFlagsWord() const
{
  return m_flags;
}

unsigned long ProcessStatus::getNumMinorFaults() const
{
  return m_minflt;
}

unsigned long ProcessStatus::getNumChildrenMinorFaults() const
{
  return m_cminflt;
}

unsigned long ProcessStatus::getNumMajorFaults() const
{
  return m_majflt;
}

unsigned long ProcessStatus::getNumChildrenMajorFaults() const
{
  return m_cmajflt;
}

unsigned long ProcessStatus::getTicksScheduledInUsermode() const
{
  return m_utime;
}

unsigned long ProcessStatus::getTicksScheduledInKernelmode() const
{
  return m_stime;
}

unsigned long ProcessStatus::getTicksChildrenScheduledInUsermode() const
{
  return m_cutime;
}

unsigned long ProcessStatus::getTicksChildrenScheduledInKernelmode() const
{
  return m_cstime;
}

long ProcessStatus::getPriority() const
{
  return m_priority;
}

long ProcessStatus::getNice() const
{
  return m_nice;
}

long ProcessStatus::getNumThreads() const
{
  return m_num_threads;
}

uint64_t ProcessStatus::getStartTime() const
{
  return m_starttime;
}

unsigned long ProcessStatus::getVirtualMemorySize() const
{
  return m_vsize;
}

long ProcessStatus::getResidentSetSize() const
{
  return m_rss;
}

unsigned long ProcessStatus::getResidentSetLimit() const
{
  return m_rsslim;
}

uintptr_t ProcessStatus::getCodeStart() const
{
  return m_startcode;
}

uintptr_t ProcessStatus::getCodeEnd() const
{
  return m_endcode;
}

uintptr_t ProcessStatus::getStackStart() const
{
  return m_startstack;
}

uintptr_t ProcessStatus::getStackPointer() const
{
  return m_kstkesp;
}

uintptr_t ProcessStatus::getInstructionPointer() const
{
  return m_kstkeip;
}

unsigned long ProcessStatus::getWaitChannel() const
{
  return m_wchan;
}

int ProcessStatus::getExitSignal() const
{
  return m_exit_signal;
}

int ProcessStatus::getCpuNumber() const
{
  return m_processor;
}

unsigned int ProcessStatus::getRealtimePriority() const
{
  return m_rt_priority;
}

unsigned int ProcessStatus::getSchedulingPolicy() const
{
  return m_policy;
}

uint64_t ProcessStatus::getIoDelays() const
{
  return m_delayacct_blkio_ticks;
}

unsigned long ProcessStatus::getGuestTime() const
{
  return m_guest_time;
}

long ProcessStatus::getChildrenGuestTime() const
{
  return m_cguest_time;
}

/* ProcessIterator class */

ProcessIterator::ProcessIterator()
  : m_current(), m_iter()
{ }

ProcessIterator::ProcessIterator(int)
  : m_current(), m_iter("/proc")
{
  // Increment to point to the first entry
  increment();
}

bool ProcessIterator::isValid() const
{
  return m_iter != boost::filesystem::directory_iterator();
}

void ProcessIterator::increment()
{
  if(!isValid())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
    ErrorString("Invalid attempt to increment Iterator"));
  }

  // Skip all non-process directories and assign.
  for(++m_iter; isValid() && !isNumericOnly(m_iter->filename()); ++m_iter);
  m_current = isValid() ? Process(*m_iter) : Process();
}

bool ProcessIterator::equal(ProcessIterator const& other) const
{
  // Only returns pseudo-equality.
  return this->isValid() == other.isValid();
}

Process& ProcessIterator::dereference() const
{
  return m_current;
}

/** Free functions **/

ProcessSequence Ethon::makeProcessSequence()
{
  return std::make_pair<ProcessIterator, ProcessIterator>(
          ProcessIterator(1), ProcessIterator());
}

Process const& Ethon::getCurrentProcess()
{
  static Process const proc(::getpid());
  return proc;
}

boost::optional<Process>
  Ethon::getProcessByName(std::string const& processName)
{
  // We can only use the first 15 bytes.
  auto begin = processName.begin(), end = processName.end();
  auto maybe = begin + 15;
  std::string name(begin, maybe > end ? end : maybe);
  
  // Iterate all processes.
  ProcessSequence sequence = Ethon::makeProcessSequence();
  BOOST_FOREACH(Process const& cur, sequence)
  {
    ProcessStatus status;
    cur.getStatus(status);
    if(name == status.getExecutableName())
      return boost::optional<Process>(cur);
  }

  // No match.
  return boost::optional<Process>();
}

std::vector<Process>
  Ethon::getProcessListByName(std::string const& processName)
{
  // We can only use the first 15 bytes.
  auto begin = processName.cbegin(), end = processName.cend();
  auto maybe = begin + 15;
  std::string name(begin, maybe > end ? end : maybe);
  
  // Iterate all processes.
  std::vector<Process> temp;
  ProcessSequence seq = Ethon::makeProcessSequence();
  BOOST_FOREACH(Process const& cur, seq)
  {
    ProcessStatus status;
    cur.getStatus(status);
    if(name == status.getExecutableName())
      temp.push_back(cur);
  }

  // Return matches.
  return temp;
}

uint8_t Ethon::getProcessImageBits(Process const& proc)
{
  // We need to read a few bytes to determine archtitecture.
  boost::filesystem::ifstream exe(proc.getExecutablePath());
  if(!exe.is_open())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Error opening executeable of process for reading."));
  }

  // Read ELF ident.
  uint8_t ident[EI_NIDENT];
  exe.read(reinterpret_cast<char*>(&ident), EI_NIDENT);

  // Check magic.
  uint32_t magic = *reinterpret_cast<const uint32_t*>(&ELFMAG[0]); 
  if(*reinterpret_cast<uint32_t*>(&ident[EI_MAG0]) != magic)
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("No valid ELF file: Wrong magic number."));
  }

  // Convert class to bits and return.
  switch(ident[EI_CLASS])
  {
  case ELFCLASSNONE:
    return 0;

  case ELFCLASS32:
    return 32;

  case ELFCLASS64:
    return 64;

  default:
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Unknown ELF class."));
  }
}
