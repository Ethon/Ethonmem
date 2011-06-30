/*
Error.hpp
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

#ifndef __ETHON_ERROR_HPP__
#define __ETHON_ERROR_HPP__

// C++ Standard Library:
#include <string>
#include <stdexcept>
#include <system_error>
#include <iostream>

// Boost Library:
#include <boost/exception/all.hpp>

namespace Ethon
{
  // A string describing the error
  typedef boost::error_info<struct ErrorStringTag, std::string> ErrorString;

  // A system error code (errno on POSIX)
  typedef boost::error_info<struct ErrorCodeTag, std::error_code> ErrorCode;

  // Base exception class
  class EthonError
    : public virtual std::exception, public virtual boost::exception
  { };
  
  // Will be thrown whenever an argument is invalid.
  class ArgumentError
    : public EthonError
  { };
  
  // Will be thrown whenever something doesn't behave like it should, mostly
  // caused by a different configuration (for example, when procfs is
  // not mounted).
  class UnexpectedError
    : public EthonError
  { };
  
  // Will be thrown whenver a system call fails.
  class SystemApiError
    : public EthonError
  { };
  
  // Will be thrown whenever a problem operating on the filesystem occurs.
  class FilesystemError
    : public SystemApiError
  { };

  // Records the current set system error code.
  std::error_code makeErrorCode();

  // Prints an EthonError-Exception to a stream.
  void printError(EthonError const& e, std::ostream& o = std::cerr);
}

#endif // __ETHON_ERROR_HPP__
