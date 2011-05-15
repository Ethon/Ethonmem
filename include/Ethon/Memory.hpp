/*
Memory.hpp
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

#ifndef __ETHON_MEMORY_HPP__
#define __ETHON_MEMORY_HPP__

// C++ Standard Library:
#include <type_traits>
#include <cstdint>

// Boost Library:
#include <boost/filesystem/fstream.hpp>
#include <boost/noncopyable.hpp>

// Ethon:
#include <Ethon/Debugger.hpp>
#include <Ethon/Error.hpp>
#include <Ethon/Processes.hpp>

namespace Ethon
{
  /**
  * Specifies access modes.
  */
  enum class AccessMode
  {
    READ,
    WRITE,
    READWRITE
  };
  
  /**
  * Class allowing to read/write a process' memory.
  */
  class MemoryEditor
  {
  private:
    Debugger m_debugger;
    int m_file;

  public:
    /**
    * Constructor initializing from a process object.
    * Memoryaccess will be read-only, unless the targeted process is traced
    * by us or forcedWritemode is set true.
    * @param process Process to attach to.
    * @param access Specifies a value from AccessMode. READWRITE is default.
    */
    MemoryEditor(Debugger const& process, AccessMode access = AccessMode::READWRITE);

    /**
    * Copy-Constructor.
    * @param other MemoryEditor to copy.
    */
    MemoryEditor(MemoryEditor const& other);

    /**
    * Assignment operator.
    * @param other MemoryEditor to assign.
    * @return this
    */
    MemoryEditor& operator=(MemoryEditor const& other);
    
    /**
    * Destructor cleaning up handles.
    */
    ~MemoryEditor();

    /**
    * Returns the process.
    * @return The process.
    */
    Process const& getProcess() const;
    
    /**
    * Returns the debugger.
    * @return The debugger.
    */
    Debugger const& getDebugger() const;

    /**
    * Determines if it is possible to read from an address.
    * @param address Address to check.
    * @return True if readable, false otherwise.
    */
    bool isReadable(uintptr_t address) const;

    /**
    * Determines if it is possible to write to an address.
    * @param address Address to check.
    * @return True if writeable, false otherwise.
    */
    bool isWriteable(uintptr_t address) const;

    /**
    * Reads a chunk of memory from the process.
    * @param address Address to read from.
    * @param dest Pointer to buffer.
    * @param amount Amount of bytes to read.
    * @return Amount of read bytes.
    */
    size_t read(uintptr_t address, void* dest, size_t amount);

    /**
    * Writes a chunk of memory to the process.
    * @param address Address to write to.
    * @param source Pointer to source.
    * @param amount Amount of bytes to write.
    * @return Amount of written bytes.
    */
    size_t write(uintptr_t address, const void* source, size_t amount);

    /**
    * Reads a POD value from the process.
    * @param address Address to read from.
    * @return The read value.
    */
    template <typename T>
    T read(uintptr_t address,
      typename std::enable_if<std::is_pod<T>::value,T>::type* /*dummy*/ = 0)
    {
      T temp;
      size_t readBytes = read(address, static_cast<void*>(&temp), sizeof(T));
      if(readBytes != sizeof(T))
      {
        BOOST_THROW_EXCEPTION(EthonError() <<
          ErrorString("Wrong amount of bytes read"));
      }

      return temp;
    }

    /**
    * Reads a string from the process.
    * @param address Address to read from.
    * @return The read string.
    */
    template <typename T>
    T read(uintptr_t address, typename std::enable_if<std::is_same<T, std::
      basic_string<typename T::value_type>>::value, T>::type* /*dummy*/ = 0)
    {
      typedef typename T::value_type char_t;

      T temp;
      char_t cur = read<char_t>(address);
      for(size_t i = 0; cur != '\0'; ++i, cur = read<char_t>(address + i))
        temp.push_back(cur);

      return temp;
    }

    /**
    * Reads a vector of POD values from the process.
    * @param address Address to read from.
    * @return The read vector.
    */
    template <typename T>
    T read(uintptr_t address, size_t amount, typename std::enable_if<std::
      is_same<T, std::vector<typename T::value_type>>::value, T>::type*
      /*dummy*/ = 0)
    {
      typedef typename T::value_type data_t;
      static_assert(std::is_pod<data_t>::value,
        "MemoryEditor::read() Error : No POD value");

      T temp(amount);
      size_t readBytes = read(
        address, static_cast<void*>(&temp[0]), sizeof(data_t) * amount);
      if(readBytes != sizeof(T))
      {
        BOOST_THROW_EXCEPTION(EthonError() <<
          ErrorString("Wrong amount of bytes read"));
      }

      return temp;
    }

    /**
    * Writes a POD value to the process.
    * @param address Address to write to.
    * @param value Value to write.
    * @return Amount of written bytes.
    */
    template <typename T>
    size_t write(uintptr_t address, T const& value,
      typename std::enable_if<std::is_pod<T>::value,T>::type* /*dummy*/ = 0)
    {
      size_t writtenBytes = write(
        address, static_cast<const void*>(&value), sizeof(T));
      if(writtenBytes != sizeof(T))
      {
        BOOST_THROW_EXCEPTION(EthonError() <<
          ErrorString("Wrong amount of bytes written"));
      }

      return writtenBytes;
    }

    /**
    * Writes a string to the process.
    * @param address Address to write to.
    * @param value String to write.
    * @return Amount of written bytes.
    */
    template <typename T>
    size_t write(uintptr_t address, T const& value, typename std::enable_if<
      std::is_same<T, std::basic_string<typename T::value_type>>::value, T>::
      type* /*dumm*/y = 0)
    {
      typedef typename T::value_type char_t;

      size_t const size = sizeof(char_t) * (value.length() + 1);
      size_t writtenBytes = write(
        address, static_cast<const void*>(value.c_str()), size);
      if(writtenBytes != size)
      {
        BOOST_THROW_EXCEPTION(EthonError() <<
          ErrorString("Wrong amount of bytes written"));
      }

      return writtenBytes;
    }

    /**
    * Writes a vector of POD value to the process.
    * @param address Address to write to.
    * @param value Vector to write.
    * @return Amount of written bytes.
    */
    template <typename T>
    size_t write(uintptr_t address, T const& value, typename std::enable_if<
      std::is_same<T, std::vector<typename T::value_type>>::value, T>::type*
      /*dummy*/ = 0)
    {
      typedef typename T::value_type data_t;
      static_assert(std::is_pod<data_t>::value,
        "MemoryEditor::write() Error : No POD value");

      size_t const size = sizeof(data_t) * value.size();
      size_t writtenBytes = write(
        address, static_cast<const void*>(&value[0]), size);
      if(writtenBytes != size)
      {
        BOOST_THROW_EXCEPTION(EthonError() <<
          ErrorString("Wrong amount of bytes written"));
      }

      return writtenBytes;
    }
  };
}

#endif // __ETHON_MEMORY_HPP__
