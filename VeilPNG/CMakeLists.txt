set(SOURCES
  data_embed.c
  encryption.c
  png_handler.c
  sveil_common.c
  sveil_embed.c
  sveil_extract.c
  sveil_png_utils.c
)

add_library(veilpng_core ${SOURCES})
target_include_directories(veilpng_core PUBLIC ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_SOURCE_DIR}/compat)
target_compile_options(veilpng_core PRIVATE $<$<NOT:$<BOOL:WIN32>>:-I${CMAKE_SOURCE_DIR}/compat>)

find_package(ZLIB REQUIRED)
target_link_libraries(veilpng_core PUBLIC ZLIB::ZLIB)

if(NOT WIN32)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(veilpng_core PUBLIC OpenSSL::Crypto)
endif()

