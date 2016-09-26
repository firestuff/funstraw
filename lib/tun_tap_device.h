#include <string>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace funstraw {

class TunTapDevice {
 public:
  static const auto kIfFormatTun = IFF_TUN;
  static const auto kIfFormatTap = IFF_TAP;
  static const auto kIfNoPacketInfo = IFF_NO_PI;

  static const auto kFdReadOnly = O_RDONLY;
  static const auto kFdWriteOnly = O_WRONLY;
  static const auto kFdReadWrite = O_RDWR;

  TunTapDevice(const std::string& name, uint64_t if_flags, uint64_t fd_flags);
  ~TunTapDevice();

  const std::string& Name() { return name_; }

  // TODO: real buffer object
  size_t Read(char* buf);

 private:
  int fd_;
  std::string name_;
};

}  // namespace funstraw
