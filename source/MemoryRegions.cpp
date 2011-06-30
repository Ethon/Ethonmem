/*
MemoryRegions.cpp
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

// C++ Standard Library:
#include <string>
#include <array>
#include <deque>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <utility>

// Boost Library:
#include <boost/lexical_cast.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/optional.hpp>
#include <boost/foreach.hpp>

// Ethonmem:
#include <Ethon/Error.hpp>
#include <Ethon/MemoryRegions.hpp>
#include <Ethon/Processes.hpp>

using Ethon::MemoryRegion;
using Ethon::MemoryRegionIterator;
using Ethon::EthonError;
using Ethon::MemoryRegionSequence;

/* MemoryRegion class */

MemoryRegion::MemoryRegion(std::string const& entryLine)
  : m_start(0), m_end(0), m_perms(), m_offset(0), m_devMajor(0),
    m_devMinor(0), m_inode(0), m_path("")
{
  std::array<char, 1024> pathBuffer;
  /*int count =*/ sscanf(entryLine.c_str(), "%lx-%lx %4s %x %hx:%hx %u %1024s",
    &m_start, &m_end, &m_perms[0], &m_offset, &m_devMajor, &m_devMinor,
    &m_inode, &pathBuffer[0]);

  m_path.assign(&pathBuffer[0]);
}

MemoryRegion::MemoryRegion()
  : m_start(0), m_end(0), m_perms(), m_offset(0), m_devMajor(0),
    m_devMinor(0), m_inode(0), m_path("")
{
  std::fill(m_perms.begin(), m_perms.end(), '-');
}

uintptr_t MemoryRegion::getStartAddress() const
{
  return m_start;
}

uintptr_t MemoryRegion::getEndAddress() const
{
  return m_end;
}

size_t MemoryRegion::getSize() const
{
  return m_end - m_start;
}

bool MemoryRegion::isReadable() const
{
  return m_perms[Perm_Read] == 'r';
}

bool MemoryRegion::isWriteable() const
{
  return m_perms[Perm_Write] == 'w';
}

bool MemoryRegion::isExecuteable() const
{
  return m_perms[Perm_Execute] == 'x';
}

bool MemoryRegion::isShared() const
{
  return m_perms[Perm_Shared] == 's';
}

bool MemoryRegion::isPrivate() const
{
  return m_perms[Perm_Shared] == 'p';
}

const std::array<char, 4>& MemoryRegion::getPermissions() const
{
  return m_perms;
}

uint32_t MemoryRegion::getOffset() const
{
  return m_offset;
}

uint16_t MemoryRegion::getDeviceMajor() const
{
  return m_devMajor;
}

uint16_t MemoryRegion::getDeviceMinor() const
{
  return m_devMinor;
}

uint32_t MemoryRegion::getInode() const
{
  return m_inode;
}

const std::string& MemoryRegion::getPath() const
{
  return m_path;
}

/* MemoryRegionIterator class */

MemoryRegionIterator::MemoryRegionIterator()
  : m_current(), m_entries()
{ }

MemoryRegionIterator::MemoryRegionIterator(Process const& process)
  : m_current(), m_entries()
{
  // Make path.
  boost::filesystem::path path(process.getProcfsDirectory());
  path /= "maps";
  if(!boost::filesystem::exists(path))
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Can't locate maps-file"));
  }

  // Open path.
  boost::filesystem::ifstream mapsFile(path);
  if(!mapsFile.is_open())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Can't open maps-file"));
  }

  // Copy all entries to buffer.
  while(mapsFile.good())
  {
    std::string current;
    std::getline(mapsFile, current);
    m_entries.push_back(std::move(current));
  }

  if(m_entries.size() <= 1)
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
      ErrorString("Couldn't read region entries from maps-file"));
  }

  // Set to first entry.
  increment();
}

bool MemoryRegionIterator::isValid() const
{
  return m_entries.size() != 0;
}

void MemoryRegionIterator::increment()
{
  if(!isValid())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
    ErrorString("Invalid attempt to increment Iterator"));
  }

  // Get memory region entry.
  std::string& line = m_entries.front();
  m_current = MemoryRegion(line);

  // Pop entry out of buffer.
  m_entries.pop_front();
}

bool MemoryRegionIterator::equal(MemoryRegionIterator const& other) const
{
  // Only returns pseudo-equality.
  return this->isValid() == other.isValid();
}

MemoryRegion& MemoryRegionIterator::dereference() const
{
  return m_current;
}


MemoryRegionSequence Ethon::makeMemoryRegionSequence(Process const& process)
{
  return std::make_pair<MemoryRegionIterator, MemoryRegionIterator>(
          MemoryRegionIterator(process), MemoryRegionIterator());
}

boost::optional<MemoryRegion> Ethon::getMatchingRegion(
  Process const& process, uintptr_t address)
{
  MemoryRegionSequence seq = Ethon::makeMemoryRegionSequence(process);
  BOOST_FOREACH(MemoryRegion const& cur, seq)
  {
    if(cur.getStartAddress() >= address && cur.getEndAddress() <= address)
      return boost::optional<MemoryRegion>(cur);
  }
  
  return boost::optional<MemoryRegion>();
}
