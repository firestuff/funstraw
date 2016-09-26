#include "lib/tun_tap_device.h"

#include "glog/logging.h"

using funstraw::TunTapDevice;

int main(int argc, char* argv[]) {
  google::InitGoogleLogging(argv[0]);

  TunTapDevice dev("", TunTapDevice::kIfFormatTun | TunTapDevice::kIfNoPacketInfo, TunTapDevice::kFdReadOnly);

  LOG(INFO) << "Device: " << dev.Name();
  while (true) {
    char buf[2048];
    auto bytes = dev.Read(buf);
    LOG(INFO) << bytes << " byte packet";
  }
}
