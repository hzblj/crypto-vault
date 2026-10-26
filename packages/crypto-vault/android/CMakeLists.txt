project(CryptoVault)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME CryptoVault)
set(CMAKE_CXX_STANDARD 20)

# The bridge (shared with iOS) and the platform half it calls, over JNI into VaultKeystore (Kotlin).
add_library(${PACKAGE_NAME} SHARED
  src/main/cpp/cpp-adapter.cpp
  src/main/cpp/VaultPlatformAndroid.cpp
  ../cpp/HybridCryptoVault.cpp
)

include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/CryptoVault+autolinking.cmake)

include_directories(
  "src/main/cpp"
  "../cpp"
)

# nitro-crypto's engine and its native interop, from its prefab package, which Gradle names after the project
# autolinking makes of @hzblj/nitro-crypto: the seeds this vault unseals are made in that engine, the one the app's
# JavaScript already talks to.
find_package(hzblj_nitro-crypto REQUIRED CONFIG)

find_library(LOG_LIB log)

target_link_libraries(
  ${PACKAGE_NAME}
  hzblj_nitro-crypto::NitroCrypto
  ${LOG_LIB}
  android
)
