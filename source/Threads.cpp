/*
Threads.cpp
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

// C++ Standard Library:
#include <utility>
#include <string>

// Boost Library:
#include <boost/filesystem.hpp>
#include <boost/iterator/iterator_facade.hpp>

// Ethon:
#include <Ethon/Processes.hpp>
#include <Ethon/Threads.hpp>
#include <Ethon/Error.hpp>

using Ethon::Process;
using Ethon::Thread;
using Ethon::ThreadIterator;
using Ethon::EthonError;
using Ethon::ThreadSequence;
using Ethon::Pid;

/* ThreadIterator class */

ThreadIterator::ThreadIterator()
  : m_current(), m_iter()
{ }

ThreadIterator::ThreadIterator(Process const& process)
  : m_current(), m_iter(process.getProcfsDirectory() / "task")
{
  // Increment to point to the first entry
  increment();
}

bool ThreadIterator::isValid() const
{
  return m_iter != boost::filesystem::directory_iterator();
}

void ThreadIterator::increment()
{
  if(!isValid())
  {
    BOOST_THROW_EXCEPTION(EthonError() <<
    ErrorString("Invalid attempt to increment Iterator"));
  }

  m_current = Thread(*m_iter++);
}

bool ThreadIterator::equal(ThreadIterator const& other) const
{
  // Only returns pseudo-equality.
  return this->isValid() == other.isValid();
}

Thread& ThreadIterator::dereference() const
{
  return m_current;
}

/** Free functions **/

ThreadSequence Ethon::makeThreadSequence(Process const& process)
{
  return std::make_pair<ThreadIterator, ThreadIterator>(
          ThreadIterator(process), ThreadIterator());
}
