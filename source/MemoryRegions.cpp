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
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <utility>
#include <cassert>

// Boost Library:
#include <boost/iterator/iterator_facade.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/foreach.hpp>

// Ethonmem:
#include <Ethon/Error.hpp>
#include <Ethon/MemoryRegions.hpp>
#include <Ethon/Processes.hpp>

using Ethon::MemoryRegion;
using Ethon::MemoryRegionIterator;
using Ethon::UnexpectedError;
using Ethon::FilesystemError;
using Ethon::MemoryRegionSequence;

/* MemoryRegion class */
MemoryRegion::MemoryRegion()
  : m_start(0), m_end(0), m_perms(), m_offset(0), m_devMajor(0),
    m_devMinor(0), m_inode(0), m_path()
{
  std::fill(m_perms.begin(), m_perms.end(), '-');
}

std::uintptr_t MemoryRegion::getStartAddress() const
{
  return m_start;
}

std::uintptr_t MemoryRegion::getEndAddress() const
{
  return m_end;
}

std::size_t MemoryRegion::getSize() const
{
  return m_end - m_start;
}

bool MemoryRegion::isReadable() const
{
  return m_perms[kPerm_Read] == 'r';
}

bool MemoryRegion::isWriteable() const
{
  return m_perms[kPerm_Write] == 'w';
}

bool MemoryRegion::isExecuteable() const
{
  return m_perms[kPerm_Execute] == 'x';
}

bool MemoryRegion::isShared() const
{
  return m_perms[kPerm_Shared] == 's';
}

bool MemoryRegion::isPrivate() const
{
  return m_perms[kPerm_Shared] == 'p';
}

const std::array<char, 4>& MemoryRegion::getPermissions() const
{
  return m_perms;
}

std::uint32_t MemoryRegion::getOffset() const
{
  return m_offset;
}

std::uint16_t MemoryRegion::getDeviceMajor() const
{
  return m_devMajor;
}

std::uint16_t MemoryRegion::getDeviceMinor() const
{
  return m_devMinor;
}

std::uint32_t MemoryRegion::getInode() const
{
  return m_inode;
}

const std::string& MemoryRegion::getPath() const
{
  return m_path;
}

/* MemoryRegionIterator class */

MemoryRegionIterator::MemoryRegionIterator()
  : m_current(), m_maps(NULL)
{ }

MemoryRegionIterator::MemoryRegionIterator(Process const& process)
  : m_current(),
    m_maps(fopen((process.getProcfsDirectory()/"maps").string().c_str(), "r"))
{
  if(!m_maps)
  {
    BOOST_THROW_EXCEPTION(FilesystemError() <<
      ErrorString("Can't open maps-file"));
  }

  // Set to first entry.
  increment();
}

MemoryRegionIterator::MemoryRegionIterator(MemoryRegionIterator&& other)
  : m_current(other.m_current), m_maps(other.m_maps)
{
  other.m_maps = NULL;
}

MemoryRegionIterator& MemoryRegionIterator::operator=(
  MemoryRegionIterator&& other)
{
  m_current = other.m_current;
  
  if(m_maps)
    fclose(m_maps);
  m_maps = other.m_maps;
  other.m_maps = NULL;
  
  return *this;
}

MemoryRegionIterator::~MemoryRegionIterator()
{
  if(m_maps)
    fclose(m_maps);
}

bool MemoryRegionIterator::isValid() const
{
  return m_maps && !feof(m_maps) && !ferror(m_maps);
}

void MemoryRegionIterator::parse(char const* line)
{
  std::array<char, 1024> pathBuffer;
  pathBuffer[0] = '\0';
  sscanf(line, "%lx-%lx %4s %x %hx:%hx %u %1024s",
    &m_current.m_start, &m_current.m_end, &m_current.m_perms[0],
    &m_current.m_offset, &m_current.m_devMajor, &m_current.m_devMinor,
    &m_current.m_inode, &pathBuffer[0]);

  m_current.m_path.assign(&pathBuffer[0]);
}

void MemoryRegionIterator::increment()
{
  assert(isValid());

  std::array<char, 1152> lineBuffer;
  fgets(&lineBuffer[0], 1152, m_maps);
  parse(&lineBuffer[0]);
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
