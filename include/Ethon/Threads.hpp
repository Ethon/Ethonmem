/*
Threads.hpp
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

#ifndef __ETHON_THREADS_HPP__
#define __ETHON_THREADS_HPP__

// C++ Standard Library:
#include <utility>
#include <algorithm>

// Boost Library:
#include <boost/filesystem.hpp>
#include <boost/iterator/iterator_facade.hpp>

// Ethon:
#include <Ethon/Processes.hpp>

namespace Ethon
{
  typedef Process Thread;
  typedef ProcessStatus ThreadStatus;

  class ThreadIterator
    : public boost::iterator_facade<  ThreadIterator,
                                      Thread,
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
    bool equal(ThreadIterator const& other) const;

    /**
    * Returns a reference to the current entry.
    * @return A reference to the current entry.
    */
    Thread& dereference() const;

    mutable Thread m_current;
    boost::filesystem::directory_iterator m_iter;

  public:

    /**
    * Default constructor creating an invalid iterator.
    */
    ThreadIterator();

    /**
    * Constructor creating an iterator for iterating running threads.
    * @param process Process to examine.
    */
    explicit ThreadIterator(Process const& process);

    /**
    * Checks if the iterator is (still) valid.
    * @return True if valid, else otherwise.
    */
    bool isValid() const;
  };

  typedef std::pair<ThreadIterator, ThreadIterator> ThreadSequence;

  /**
  * Enumerates all running threads of a process.
  * @param process The Process.
  * @param f Functor to be called every entry with a Thread as argument.
  * @return The functor f.
  */
  template<typename functor_t>
  functor_t enumThreads(Process const& process, functor_t f)
  {
    return std::for_each(ThreadIterator(process.getPid()),
            ProcessIterator(), f);
  }

  /**
  * Makes a pair of ThreadIterators, which can be used to iterate threads.
  * @param process The process.
  * @return A pair of ThreadIterators.
  */
  ThreadSequence makeThreadSequence(Process const& process);
}

#endif // __ETHON_THREADS_HPP__
