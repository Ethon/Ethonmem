// C++ Header Files:
#include <iostream>

// Ethon Header Files:
#include <Ethon/Processes.hpp>
#include <Ethon/Threads.hpp>
#include <Ethon/Error.hpp>

int main()
{
  try
  {
    Ethon::enumProcesses([&](Ethon::Process const& proc)
    {
      std::cout << "\n" << proc.getPid() << " " <<
        proc.getStatus().getExecutableName() << "\n";

      Ethon::enumThreads(proc, [&](Ethon::Thread const& thread)
      {
        std::cout << "\t" << thread.getPid() << "\n";
      });  
    });
  }
  catch(Ethon::EthonError const& e)
  {
    Ethon::printError(e, std::cerr);
  }
}