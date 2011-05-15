#include <boost/python.hpp>
#include <boost/filesystem.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(ethonmem)
{
  class_<boost::filesystem::path>("Path")
    .add_property("string", &boost::filesystem::path::string)
    .add_property("filename", &boost::filesystem::path::filename)
    ;
}
