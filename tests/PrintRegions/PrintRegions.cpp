// C++ Header Files:
#include <iostream>
#include <iomanip>

// Boost Header Files:
#include <boost/lexical_cast.hpp> 

// Ethon Header Files:
#include <Ethon/MemoryRegions.hpp>
#include <Ethon/Processes.hpp>
#include <Ethon/Error.hpp>

std::ostream& operator<<(std::ostream& lhs, Ethon::MemoryRegion const& rhs)
{
  lhs << "-- Region at 0x" << std::hex << rhs.getStartAddress() << " --\n";
  lhs << "\tSize: 0x" << rhs.getSize() << "\n\tMapped File: " << rhs.getPath();
  lhs << std::endl;

  return lhs;
}

int main(int argc, char** argv)
{
  try
  {
    if(argc > 1)
    {
      Ethon::Process proc(boost::lexical_cast<Ethon::Pid>(argv[1]));
      Ethon::enumMemoryRegions(proc, [&](Ethon::MemoryRegion const& reg)
      {
        std::cout << reg << std::endl;
      });
    }
  }
  catch(Ethon::EthonError const& e)
  {
    Ethon::printError(e, std::cerr);
  }
}