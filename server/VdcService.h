#pragma once

#include <android/net/vdc/aidl/BnVdc.h>
#include <binder/BinderService.h>

namespace android::net {

class VdcService : public android::net::vdc::aidl::BnVdc {
  public:
    static status_t start();
    static char const* getServiceName() { return "vdc"; }

    binder::Status startDaemon() override;
};

}  // namespace android::net
