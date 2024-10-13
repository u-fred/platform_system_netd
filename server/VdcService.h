#pragma once

#include <android/net/vdc/aidl/BnVdc.h>
#include <binder/BinderService.h>

namespace android::net {

// TODO: Rename to INetdExt
class VdcService : public android::net::vdc::aidl::BnVdc {
  public:
    static status_t start();
    static char const* getServiceName() { return "vdc"; }

    binder::Status startDaemon() override;
    binder::Status setVpnDnsCompatModeEnabled(int netId, bool enabled);
};

}  // namespace android::net
