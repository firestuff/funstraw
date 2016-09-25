#include <string>

#include <linux/if_tun.h>

class TapTunDevice {
 public:
  static const auto kTunFormat = IFF_TUN;
  static const auto kTapFormat = IFF_TAP;
  static const auto kNoPacketInfo = IFF_NO_PI;

	TapTunDevice(const std::string& name, uint64_t flags);
	TapTunDevice(uint64_t flags);

  const std::string& Name() {
    return name_;
  }

 private:
  std::string name_;
};

