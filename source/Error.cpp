/*
Error.cpp
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
#include <string>
#include <stdexcept>
#include <system_error>
#include <cerrno>
#include <iostream>
#include <array>

// Boost Library:
#include <boost/exception/all.hpp>

// Ethon:
#include <Ethon/Error.hpp>

using Ethon::EthonError;
using Ethon::ErrorString;
using Ethon::ErrorCode;

std::error_code Ethon::makeErrorCode()
{
  return std::error_code(errno, std::system_category());
}

void Ethon::printError(EthonError const& e, std::ostream& o)
{
  o << "Exception occured in "
    << *boost::get_error_info<boost::throw_function>(e) << "\n"
    << "Description: " << *boost::get_error_info<ErrorString>(e) << "\n";

  std::error_code const* errorCode = boost::get_error_info<ErrorCode>(e);
  if(errorCode)
  {
    std::array<char, 64> buffer;
    char* str = ::strerror_r(errorCode->value(), &buffer[0], buffer.size());

    o << "Errorcode: " << errorCode->value() << " (" << str << ")\n";
  }

  o << "File: " << *boost::get_error_info<boost::throw_file>(e) << " ("
    << *boost::get_error_info<boost::throw_line>(e) << ")\n";
}
