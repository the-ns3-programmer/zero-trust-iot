# Default: Crypto++ disabled
set(ENABLE_CRYPTOPP
    False
    CACHE INTERNAL ""
)

# Allow user to request Crypto++ explicitly
option(NS3_CRYPTOPP "Enable Crypto++ support in zero-trust-iot" OFF)

if(NS3_CRYPTOPP)
  find_package(PkgConfig REQUIRED)

  # Look for Crypto++ via pkg-config
  pkg_check_modules(CRYPTOPP cryptopp)

  if(CRYPTOPP_FOUND)
    message(STATUS "Crypto++ found")
    set(ENABLE_CRYPTOPP True CACHE INTERNAL "")
    include_directories(${CRYPTOPP_INCLUDE_DIRS})
    add_definitions(-DENABLE_CRYPTOPP)
  else()
    message(FATAL_ERROR "NS3_CRYPTOPP=ON but Crypto++ not found via pkg-config")
  endif()
else()
  message(STATUS "Crypto++ support explicitly disabled (NS3_CRYPTOPP=OFF)")
endif()

# Sources/headers
set(crypto_sources)
set(crypto_headers)
set(crypto_libraries)

if(ENABLE_CRYPTOPP)
  set(crypto_sources
      model/zt-certificate.cc
      model/zt-encryption-utils.cc
      model/zt-policy-engine.cc
      model/zt-logger.cc
      model/zt-tls-handshake.cc
      model/zt-hash-utils.cc
      model/zt-identity-registry.cc
      model/zt-ipv4-hook.cc
      
  )
  set(crypto_headers
      model/zt-certificate.h
      model/zt-encryption-utils.h
      model/zt-policy-engine.h
      model/zt-logger.h
      model/zt-tls-handshake.h
      model/zt-hash-utils.h
      model/zt-identity-registry.h
      model/zt-ipv4-hook.h
  )
  set(crypto_libraries ${CRYPTOPP_LIBRARIES})

  build_lib(
    LIBNAME zero-trust-iot
    SOURCE_FILES ${crypto_sources}
    
    HEADER_FILES ${crypto_headers}
    LIBRARIES_TO_LINK
      ${libcore}
      ${libnetwork}
      ${libinternet}
      ${libwifi}
      ${crypto_libraries}
  )
endif()
