#include "lib/tun_tap_device.h"

#include <sys/socket.h>
#include <linux/if.h>
#include <glog/logging.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace funstraw {

namespace {
const std::string kCloneDevice = "/dev/net/tun";
}

TunTapDevice::TunTapDevice(const std::string& name, uint64_t if_flags, uint64_t fd_flags) {
  auto fd_ = open(kCloneDevice.c_str(), fd_flags);
  CHECK_NE(fd_, -1) << strerror(errno);

  struct ifreq ifr = {0};
  ifr.ifr_flags = if_flags;
  if (!name.empty()) {
    CHECK_LT(name.length(), IFNAMSIZ);
    strcpy(ifr.ifr_name, name.c_str());
  }

  CHECK_EQ(ioctl(fd_, TUNSETIFF, &ifr), 0) << strerror(errno);

  name_ = ifr.ifr_name;
}

TunTapDevice::~TunTapDevice() {
  CHECK_EQ(close(fd_), 0);
}

size_t TunTapDevice::Read(char* buf) {
  auto bytes = read(fd_, buf, 2048);
  CHECK_NE(bytes, -1) << strerror(errno);
  return bytes;
}

}  // namespace funstraw
