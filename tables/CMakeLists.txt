cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTables)
  add_library(zeek_tables INTERFACE)


    add_subdirectory("audisp")

    add_subdirectory("endpointsecurity")


  add_subdirectory("host_information")
endfunction()

zeekAgentTables()
