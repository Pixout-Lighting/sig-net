#==============================================================================
# Sig-Net C++ FFI Example — Build
#==============================================================================
# From workspace root:
#   cd examples/signet-ffi && make run
#==============================================================================

CXX      := c++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
INCLUDES := -I../../include

TARGET := ffi-demo

.PHONY: all clean rebuild run ffi-build

all: $(TARGET)

$(TARGET): ffi-demo.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< ../../target/release/libsignet_ffi.dylib -o $@

ffi-build:
	cd ../.. && cargo build -p signet-ffi --release

run: ffi-build all
	DYLD_LIBRARY_PATH=../../target/release ./$(TARGET)

clean:
	rm -f $(TARGET)

rebuild: clean all
